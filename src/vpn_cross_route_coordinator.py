"""Two-node cross-route 2-phase coordinator with compensating rollback.

The controller must persist the operation ID in DB *before* executing this.
Never retry on an uncertain result; surface manual-recovery-required instead.
"""
from uuid import uuid4


class CrossRouteCoordinationError(RuntimeError):
    pass


def run_direct_route_transaction(source, dest, source_plan, dest_plan, sender,
                                 opid, persist_state):
    """Prepare both; commit destination then source; verify both; finalize.

    persist_state(state, source_revision, destination_revision) MUST be durable.
    The implementation is transport-agnostic; caller supplies authenticated
    mTLS sender and independently persisted operation ledger.
    """
    nodes = ((source, source_plan), (dest, dest_plan))
    prepared = {}
    prepared_unknown = False
    attempted_prepare = None
    try:
        for node, plan in nodes:
            attempted_prepare = node.name
            response = sender(node, "route-ext-prepare", plan, operation_id=opid)
            if (not isinstance(response, dict)
                    or response.get("state") != "prepared"
                    or response.get("operation_id") != opid
                    or not isinstance(response.get("revision"), str)
                    or len(response["revision"]) != 64):
                raise CrossRouteCoordinationError("No authenticated Prepare acknowledgement")
            prepared[node.name] = response["revision"]
            attempted_prepare = None
            persist_state("prepared", prepared.get(source.name), prepared.get(dest.name))
        persist_state("committing", prepared[source.name], prepared[dest.name])
        # Ensure the destination can route return traffic before the ingress
        # source begins sending client packets.
        for node, plan in ((dest, dest_plan), (source, source_plan)):
            revision = prepared[node.name]
            response = sender(node, "route-ext-commit", {
                "node_name": node.name, "address": node.ip_pool,
                "revision": revision,
            }, operation_id=opid)
            if (not isinstance(response, dict)
                    or response.get("state") != "committed"
                    or response.get("revision") != revision
                    or response.get("operation_id") != opid):
                raise CrossRouteCoordinationError("Commit acknowledgement missing")
        persist_state("verifying", prepared[source.name], prepared[dest.name])
        checks = []
        for node, plan in nodes:
            observation = sender(node, "policy-path-preview", plan)
            if (not isinstance(observation, dict)
                    or observation.get("writes_performed") is not False
                    or observation.get("gateway_checks_passed") is not True):
                raise CrossRouteCoordinationError("Bidirectional gateway verification failed")
            checks.append(observation)
        persist_state("finalizing", prepared[source.name], prepared[dest.name])
        for node, plan in nodes:
            response = sender(node, "route-ext-finalize", {
                "node_name": node.name, "address": node.ip_pool,
                "revision": prepared[node.name],
            }, operation_id=opid)
            if (not isinstance(response, dict) or response.get("state") != "finished"
                    or response.get("operation_id") != opid):
                raise CrossRouteCoordinationError("Finalize result unconfirmed")
        persist_state("committed", prepared[source.name], prepared[dest.name])
        return {"state": "committed", "operation_id": opid, "source": source.name,
                "destination": dest.name, "gateway_checks_passed": True,
                "protected_host_return_verified": False,
                "cognitor_route_verified": False}
    except Exception as exc:
        # IMPORTANT: the first peer may be committed even if the RPC times out.
        # Attempt compensation for every prepared half, in reverse order.
        # A Prepare RPC can time out after root wrote a journal. Without an
        # ACK/revision we cannot safely revert that half, so leave a durable
        # recovery_required fence and never claim rollback completed.
        unknown_prepare = attempted_prepare is not None
        try:
            persist_state("reverting", prepared.get(source.name), prepared.get(dest.name))
        except Exception:
            unknown_prepare = True
        errors = []
        for node, plan in reversed(nodes):
            revision = prepared.get(node.name)
            if revision is None:
                continue
            try:
                reply = sender(node, "route-ext-revert", {
                    "node_name": node.name, "address": node.ip_pool,
                    "revision": revision,
                }, operation_id=opid)
                if not isinstance(reply, dict) or reply.get("state") != "reverted":
                    errors.append(node.name)
            except Exception:
                errors.append(node.name)
        if errors or unknown_prepare:
            persist_state("recovery_required", prepared.get(source.name), prepared.get(dest.name))
            suspects = errors + ([attempted_prepare] if unknown_prepare and attempted_prepare else [])
            raise CrossRouteCoordinationError(
                "Distributed route outcome UNKNOWN; manual inspection on "
                + ", ".join(suspects or ["controller ledger"])) from exc
        persist_state("reverted", prepared.get(source.name), prepared.get(dest.name))
        raise CrossRouteCoordinationError("Distributed route change aborted and compensated") from exc

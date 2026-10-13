from app import app, db
from instance.vpngate import General

with app.app_context():
    affected = General.query.filter(General.role == 'Cognitor').update(
        {"sent_to_magos": False, "ack_from_magos": False}, synchronize_session=False
    )
    db.session.commit()
    print(f"Обнулено {affected} записей.")
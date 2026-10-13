from app import db

class General(db.Model):
    """
    Модель для локального состояния Magos агента
    Хранит информацию о самом агенте и подключенных Cognitor (клиентах)
    """
    __tablename__ = 'general'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='Magos')
    
    # WireGuard параметры
    ip_pool = db.Column(db.String(50))
    listen_port = db.Column(db.Integer)
    private_key = db.Column(db.Text)
    public_key = db.Column(db.Text)
    preshared_key = db.Column(db.Text)
    dns = db.Column(db.String(50))
    mtu = db.Column(db.Integer)
    endpoint = db.Column(db.String(255))
    
    # Статус
    status = db.Column(db.String(20), default='stopped')
    
    # Связи
    parent_id = db.Column(db.Integer, db.ForeignKey('general.id'), nullable=True)
    
    # Временные метки
    created_at = db.Column(db.DateTime)
    last_handshake = db.Column(db.DateTime)
    last_heartbeat = db.Column(db.DateTime)
    
    # Статистика трафика
    total_receive = db.Column(db.BigInteger, default=0)
    total_sent = db.Column(db.BigInteger, default=0)
    
    def __repr__(self):
        return f'<General {self.name} ({self.role})>'






from database import db_cursor
from security import compute_record_hmac


def refresh_user_hmac(user_id: int) -> None:
    """Recompute and store the HMAC for a users row after mutation."""
    with db_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        if not row:
            return
        record = dict(row)
        new_mac = compute_record_hmac(record)
        cur.execute("UPDATE users SET hmac = ? WHERE id = ?", (new_mac, user_id))



def refresh_customer_hmac(user_id: int) -> None:
    """Recompute and store the HMAC for a customers row after mutation."""
    with db_cursor() as cur:
        cur.execute("SELECT * FROM customers WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        if not row:
            return
        record = dict(row)
        new_mac = compute_record_hmac(record)
        cur.execute("UPDATE customers SET hmac = ? WHERE user_id = ?", (new_mac, user_id))        












        
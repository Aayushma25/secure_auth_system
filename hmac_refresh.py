
# This module provides functions to recompute and store HMACs for database records after they have been mutated.
# Each function retrieves the relevant record from the database, computes a new HMAC using the compute_record_hmac function, and updates the record with the new HMAC value.


from database import db_cursor
from security import compute_record_hmac



# The function refresh_user_hmac takes a user_id as an argument, 
# retrieves the corresponding user record from the users table, 
# computes a new HMAC for that record, and updates the hmac field in the users table with the new value.

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



# The function refresh_customer_hmac performs a similar operation for the customers table, 
    # retrieving the customer record based on the user_id, computing a new HMAC, and updating the hmac field in the customers table.

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




# The function refresh_employee_hmac does the same for the employees table, 
    # retrieving the employee record based on the user_id, computing a new HMAC, and updating the hmac field in the employees table.

def refresh_employee_hmac(user_id: int) -> None:   
    """Recompute and store the HMAC for an employees row after mutation."""
    with db_cursor() as cur:
        cur.execute("SELECT * FROM employees WHERE user_id = ?", (user_id,))  # This is used because to prevent SQL injection, we use parameterized queries instead of string formatting.
        row = cur.fetchone()                # fetchone() is used to retrieve a single record from the database. It returns a single row as a tuple, or None if no more rows are available. In this context, it retrieves the employee record corresponding to the given user_id. If no such record exists, it returns None, which is checked in the subsequent if statement.
        if not row:
            return
        record = dict(row)
        new_mac = compute_record_hmac(record)
        cur.execute("UPDATE employees SET hmac = ? WHERE user_id = ?", (new_mac, user_id))    # This line updates the hmac field in the employees table for the record with the specified user_id.
                                                                                              #  The new HMAC value is passed as a parameter to the query, ensuring that it is safely handled and preventing SQL injection vulnerabilities.









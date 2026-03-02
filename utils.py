# utils.py
from datetime import datetime
from db import get_db_connection, get_cursor
from db import get_db_connection, get_cursor

def log_monitor_action(user_id=None, username=None, action_type="", target_id=None, details="", ip_address=None):
    conn = get_db_connection()
    if not conn:
        return  # silent fail – don't crash app

    try:
        cursor = get_cursor(conn)
        cursor.execute("""
            INSERT INTO monitor_logs 
            (user_id, username, action_type, target_id, details, ip_address)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_id, username, action_type, target_id, details, ip_address))
        conn.commit()
    except Exception as e:
        print(f"Log error: {str(e)}")  # log to console – don't crash
    finally:
        conn.close()


from datetime import datetime
from db import get_db_connection, get_cursor

def create_message(receiver_user_id, message, sender_role="monitor", related_log_id=None):
    """
    Create a targeted message for a user.
    Returns True if successful, False on failure.
    """
    if not receiver_user_id or not message.strip():
        return False

    # No integer conversion! Just store the UUID string
    conn = get_db_connection()
    if not conn:
        print("[MESSAGE ERROR] No DB connection")
        return False

    try:
        cursor = get_cursor(conn)
        cursor.execute("""
            INSERT INTO messages
            (sender_role, receiver_user_id, message, related_log_id, is_read, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            sender_role,
            receiver_user_id,
                    message.strip(),
            related_log_id,
            False,
            datetime.utcnow()
        ))
        conn.commit()
        return True
    except Exception as e:
        print(f"[MESSAGE ERROR] {e}")
        return False
    finally:
        conn.close()


def get_or_create_template(template_key, title=None, content=None):
    """
    Fetch a template by key. If missing, create it with fallback content.
    Returns (template_id, content) or (None, None) on failure.
    """
    conn = get_db_connection()
    if not conn:
        return None, None

    try:
        cursor = get_cursor(conn)
        # Check if template exists
        cursor.execute("SELECT id, content FROM message_templates WHERE template_key=%s", (template_key,))
        row = cursor.fetchone()
        if row:
            return row['id'], row['content']

        # Otherwise, create template
        if not content:
            return None, None  # No content to create

        cursor.execute("""
            INSERT INTO message_templates (template_key, title, content)
            VALUES (%s, %s, %s)
            RETURNING id
        """, (template_key, title or '', content))
        template_id = cursor.fetchone()['id']
        conn.commit()
        return template_id, content
    except Exception as e:
        print(f"[TEMPLATE ERROR] {e}")
        return None, None
    finally:
        conn.close()


def get_unread_messages(user_id):
    """
    Fetch unread messages for a user.
    Returns list of dicts.
    """
    conn = get_db_connection()
    if not conn:
        return []

    try:
        cursor = get_cursor(conn)
        cursor.execute("""
            SELECT id, message, created_at
            FROM messages
            WHERE receiver_user_id=%s AND is_read=FALSE
            ORDER BY created_at ASC
        """, (user_id,))
        messages = cursor.fetchall() or []

        serialized = []
        for msg in messages:
            msg_dict = dict(msg)
            if isinstance(msg_dict.get("created_at"), datetime):
                msg_dict["created_at"] = msg_dict["created_at"].strftime('%Y-%m-%d %H:%M:%S')
            serialized.append(msg_dict)
        return serialized
    except Exception as e:
        print(f"[UNREAD FETCH ERROR] {e}")
        return []
    finally:
        conn.close()


def mark_message_as_read(msg_id, user_id):
    """
    Mark a single message as read for the user.
    Returns True if success.
    """
    conn = get_db_connection()
    if not conn:
        return False

    try:
        cursor = get_cursor(conn)
        cursor.execute("""
            UPDATE messages
            SET is_read=TRUE
            WHERE id=%s AND receiver_user_id=%s
        """, (msg_id, user_id))
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print(f"[MARK READ ERROR] {e}")
        return False
    finally:
        conn.close()

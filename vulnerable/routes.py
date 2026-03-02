# vulnerable/routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from db import get_db_connection, get_cursor
from utils import log_monitor_action
import uuid

vuln_bp = Blueprint('vuln', __name__)

# ────────────────────────────────────────────────
# HOME / LISTINGS OVERVIEW
# ────────────────────────────────────────────────
@vuln_bp.route("/")
@login_required
def home():
    conn = get_db_connection()
    if not conn:
        flash("Database connection failed!", "danger")
        return render_template("vulnerable/home.html", listings=[])

    try:
        cursor = get_cursor(conn)
        cursor.execute("""
            SELECT l.id, l.title, l.price, l.category, l.status, 
                   u.username AS owner, u.id AS owner_id
            FROM listings l
            JOIN users u ON l.user_id = u.id
            WHERE l.status = 'available'
            ORDER BY l.created_at DESC
            LIMIT 30
        """)
        listings = cursor.fetchall() or []
    except Exception as e:
        flash(f"Error loading listings: {str(e)}", "danger")
        listings = []
    finally:
        conn.close()

    return render_template("vulnerable/home.html", listings=listings)

# ────────────────────────────────────────────────
# PROFILE VIEW – IDOR VULNERABILITY
# ────────────────────────────────────────────────
@vuln_bp.route("/profile/<user_id>")
@login_required
def profile(user_id):
    conn = get_db_connection()
    try:
        cursor = get_cursor(conn)
        cursor.execute("""
            SELECT id, username, email, phone, hostel, bio, role
            FROM users
            WHERE id = %s
        """, (user_id,))
        profile_user = cursor.fetchone()

        if not profile_user:
            flash("User not found", "danger")
            return redirect(url_for("vuln.home"))

        is_own_profile = (str(user_id) == str(current_user.id))

        # Log cross-account profile views silently
        if not is_own_profile:
            log_monitor_action(
                user_id=current_user.id,
                username=current_user.username,
                action_type="profile_view_cross",
                target_id=user_id,
                details=f"Viewed profile of {profile_user['username']} (ID: {user_id})",
                ip_address=request.remote_addr
            )

        return render_template("vulnerable/profile.html", 
                               profile_user=profile_user, 
                               is_own_profile=is_own_profile)
    except Exception as e:
        flash(f"Error loading profile: {str(e)}", "danger")
        return redirect(url_for("vuln.home"))
    finally:
        conn.close()

# ────────────────────────────────────────────────
# PROFILE EDIT – Missing ownership + mass assignment
# ────────────────────────────────────────────────
@vuln_bp.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    target_user_id = request.form.get("user_id", current_user.id) if request.method == "POST" else current_user.id

    conn = get_db_connection()
    try:
        cursor = get_cursor(conn)
        cursor.execute("SELECT * FROM users WHERE id = %s", (target_user_id,))
        user_data = cursor.fetchone()

        if not user_data:
            flash("User not found", "danger")
            return redirect(url_for("vuln.home"))

        if request.method == "GET":
            return render_template("vulnerable/profile_edit.html", user=user_data)

        # POST – extract form data
        phone = request.form.get("phone", "").strip()
        hostel = request.form.get("hostel", "").strip()
        bio = request.form.get("bio", "").strip()
        role = request.form.get("role", user_data['role'])

        cursor.execute("""
            UPDATE users
            SET phone = %s, hostel = %s, bio = %s, role = %s
            WHERE id = %s
        """, (phone or None, hostel or None, bio or None, role, target_user_id))
        conn.commit()

        # Log cross-account edit silently
        if str(target_user_id) != str(current_user.id):
            log_monitor_action(
                user_id=current_user.id,
                username=current_user.username,
                action_type="profile_edit_cross",
                target_id=target_user_id,
                details=f"Edited profile of user {target_user_id} (phone/hostel/bio/role changed)",
                ip_address=request.remote_addr
            )
        # Log self role tampering
        elif role != user_data['role']:
            log_monitor_action(
                user_id=current_user.id,
                username=current_user.username,
                action_type="role_tamper_self",
                target_id=target_user_id,
                details=f"Self role changed to {role} (mass assignment)",
                ip_address=request.remote_addr
            )

        flash("Profile updated", "success")
        return redirect(url_for("vuln.profile", user_id=target_user_id))
    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for("vuln.home"))
    finally:
        conn.close()

# ────────────────────────────────────────────────
# SINGLE LISTING VIEW – IDOR VULN
# ────────────────────────────────────────────────
@vuln_bp.route("/listing/<listing_id>")
@login_required
def listing_detail(listing_id):
    conn = get_db_connection()
    try:
        cursor = get_cursor(conn)
        cursor.execute("""
            SELECT l.id, l.title, l.description, l.price, l.category, l.status,
                   u.username AS owner, u.id AS owner_id, u.phone, u.hostel
            FROM listings l
            JOIN users u ON l.user_id = u.id
            WHERE l.id = %s
        """, (listing_id,))
        item = cursor.fetchone()

        if not item:
            flash("Listing not found", "danger")
            return redirect(url_for("vuln.home"))

        is_owner = (str(item['owner_id']) == str(current_user.id))

        # Log cross-account listing view silently
        if not is_owner:
            log_monitor_action(
                user_id=current_user.id,
                username=current_user.username,
                action_type="listing_view_cross",
                target_id=listing_id,
                details=f"Viewed listing ID {listing_id} owned by {item['owner']}",
                ip_address=request.remote_addr
            )

        return render_template("vulnerable/listing_detail.html", item=item, is_owner=is_owner)

    except Exception as e:
        flash(f"Error loading listing: {str(e)}", "danger")
        return redirect(url_for("vuln.home"))
    finally:
        conn.close()

# ────────────────────────────────────────────────
# CREATE NEW LISTING – Mass Assignment VULN
# ────────────────────────────────────────────────
@vuln_bp.route("/listing/new", methods=["GET", "POST"])
@login_required
def new_listing():
    if request.method == "GET":
        return render_template("vulnerable/listing_new.html")

    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    price_str = request.form.get("price", "0").strip()
    category = request.form.get("category", "other")
    owner_id = request.form.get("owner_id", current_user.id)

    try:
        price = float(price_str)
        if price <= 0:
            raise ValueError
    except:
        flash("Invalid price", "danger")
        return redirect(url_for("vuln.new_listing"))

    if not title:
        flash("Title required", "danger")
        return redirect(url_for("vuln.new_listing"))

    conn = get_db_connection()
    try:
        cursor = get_cursor(conn)
        listing_id = str(uuid.uuid4())

        cursor.execute("""
            INSERT INTO listings 
            (id, user_id, title, description, price, category)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (listing_id, owner_id, title, description, price, category))
        conn.commit()

        # Log mass assignment silently
        if str(owner_id) != str(current_user.id):
            log_monitor_action(
                user_id=current_user.id,
                username=current_user.username,
                action_type="listing_create_tamper",
                target_id=listing_id,
                details=f"Created listing {listing_id} as user {owner_id} (mass assignment)",
                ip_address=request.remote_addr
            )

        flash("Item posted successfully!", "success")
        return redirect(url_for("vuln.home"))

    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for("vuln.new_listing"))
    finally:
        conn.close()

# ────────────────────────────────────────────────
# EDIT LISTING – Ownership bypass + mass assignment
# ────────────────────────────────────────────────
@vuln_bp.route("/listing/<listing_id>/edit", methods=["GET", "POST"])
@login_required
def edit_listing(listing_id):
    conn = get_db_connection()
    try:
        cursor = get_cursor(conn)
        cursor.execute("SELECT * FROM listings WHERE id = %s", (listing_id,))
        item = cursor.fetchone()

        if not item:
            flash("Listing not found", "danger")
            return redirect(url_for("vuln.home"))

        if request.method == "GET":
            return render_template("vulnerable/listing_edit.html", item=item)

        # POST
        title = request.form.get("title", item['title']).strip()
        description = request.form.get("description", item['description'] or "").strip()
        price_str = request.form.get("price", str(item['price'])).strip()
        category = request.form.get("category", item['category'])
        status = request.form.get("status", item['status'])
        owner_id = request.form.get("owner_id", item['user_id'])

        try:
            price = float(price_str)
        except:
            flash("Invalid price", "danger")
            return redirect(url_for("vuln.edit_listing", listing_id=listing_id))

        cursor.execute("""
            UPDATE listings
            SET title = %s, description = %s, price = %s, category = %s, 
                status = %s, user_id = %s
            WHERE id = %s
        """, (title, description, price, category, status, owner_id, listing_id))
        conn.commit()

        # Log tampering silently
        if str(owner_id) != str(current_user.id):
            log_monitor_action(
                user_id=current_user.id,
                username=current_user.username,
                action_type="listing_edit_tamper",
                target_id=listing_id,
                details=f"Edited listing {listing_id} – changed owner to {owner_id}",
                ip_address=request.remote_addr
            )
        elif status in ['sold', 'deleted'] and item['status'] != status:
            log_monitor_action(
                user_id=current_user.id,
                username=current_user.username,
                action_type="listing_status_change",
                target_id=listing_id,
                details=f"Changed listing status to {status}",
                ip_address=request.remote_addr
            )

        flash("Listing updated", "success")
        return redirect(url_for("vuln.listing_detail", listing_id=listing_id))

    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for("vuln.edit_listing", listing_id=listing_id))
    finally:
        conn.close()

# ────────────────────────────────────────────────
# DELETE LISTING – Missing ownership check
# ────────────────────────────────────────────────
@vuln_bp.route("/listing/<listing_id>/delete", methods=["POST"])
@login_required
def delete_listing(listing_id):
    conn = get_db_connection()
    try:
        cursor = get_cursor(conn)
        cursor.execute("SELECT user_id, title FROM listings WHERE id = %s", (listing_id,))
        item = cursor.fetchone()

        if not item:
            flash("Listing not found", "danger")
            return redirect(url_for("vuln.home"))

        cursor.execute("UPDATE listings SET status = 'deleted' WHERE id = %s", (listing_id,))
        conn.commit()

        # Log delete action silently
        log_monitor_action(
            user_id=current_user.id,
            username=current_user.username,
            action_type="listing_delete",
            target_id=listing_id,
            details=f"Deleted listing: {item['title']}",
            ip_address=request.remote_addr
        )

        flash("Listing deleted", "success")
        return redirect(url_for("vuln.home"))

    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for("vuln.home"))
    finally:
        conn.close()

# ────────────────────────────────────────────────
# ADMIN PANEL – Forced Browsing + Privilege Escalation
# ────────────────────────────────────────────────
@vuln_bp.route("/admin")
@login_required
def admin():
    conn = get_db_connection()
    try:
        cursor = get_cursor(conn)
        cursor.execute("SELECT id, username, role, email FROM users")
        all_users = cursor.fetchall()

        # Log admin access silently
        log_monitor_action(
            user_id=current_user.id,
            username=current_user.username,
            action_type="admin_access",
            details="Accessed admin panel",
            ip_address=request.remote_addr
        )

        return render_template("vulnerable/admin.html", all_users=all_users)
    except Exception as e:
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for("vuln.home"))
    finally:
        conn.close()


@vuln_bp.route("/favorites/add", methods=["POST"])
@login_required
def add_favorite():
    listing_id = request.form.get("listing_id")
    target_user_id = request.form.get("user_id", current_user.id)  # optional hidden field for IDOR demo

    if not listing_id:
        flash("No listing selected", "danger")
        return redirect(request.referrer or url_for("vuln.home"))

    conn = get_db_connection()
    try:
        cursor = get_cursor(conn)

        # Fetch listing info (owner/status) for logging
        cursor.execute("SELECT user_id, status FROM listings WHERE id = %s", (listing_id,))
        listing = cursor.fetchone()
        if not listing:
            flash("Listing not found", "danger")
            return redirect(request.referrer or url_for("vuln.home"))

        # Check for Broken Access Control: user_id in request != current user
        if str(target_user_id) != str(current_user.id):
            # Log the cross-user attempt
            log_monitor_action(
                user_id=current_user.id,
                username=current_user.username,
                action_type="favorite_add_bac",
                target_id=listing_id,
                details=f"Attempted to add listing {listing_id} to favorites as user {target_user_id} (owner: {listing['user_id']})",
                ip_address=request.remote_addr
            )
            flash("Cannot add favorite for another user! (Logged)", "warning")
            return redirect(request.referrer or url_for("vuln.home"))

        # Normal add favorite
        cursor.execute("""
            INSERT IGNORE INTO favorites (user_id, listing_id)
            VALUES (%s, %s)
        """, (current_user.id, listing_id))
        conn.commit()

        # # Log successful addition
        # log_monitor_action(
        #     user_id=current_user.id,
        #     username=current_user.username,
        #     action_type="favorite_add",
        #     target_id=listing_id,
        #     details=f"Added listing {listing_id} to favorites (owner: {listing['user_id']})",
        #     ip_address=request.remote_addr
        # )

        flash("Added to favorites!", "success")

    except Exception as e:
        flash(f"Error adding to favorites: {str(e)}", "danger")
    finally:
        conn.close()

    return redirect(request.referrer or url_for("vuln.home"))


@vuln_bp.route("/favorites/remove", methods=["POST"])
@login_required
def remove_favorite():
    listing_id = request.form.get("listing_id")
    target_user_id = request.form.get("user_id", current_user.id)  # optional hidden field for IDOR demo

    if not listing_id:
        flash("No listing selected", "danger")
        return redirect(request.referrer or url_for("vuln.home"))

    conn = get_db_connection()
    try:
        cursor = get_cursor(conn)

        # Fetch listing info (owner/status) for logging
        cursor.execute("SELECT user_id, status FROM listings WHERE id = %s", (listing_id,))
        listing = cursor.fetchone()
        if not listing:
            flash("Listing not found", "danger")
            return redirect(request.referrer or url_for("vuln.home"))

        # Check for Broken Access Control: user_id in request != current user
        if str(target_user_id) != str(current_user.id):
            # Log the cross-user attempt
            log_monitor_action(
                user_id=current_user.id,
                username=current_user.username,
                action_type="favorite_remove_bac",
                target_id=listing_id,
                details=f"Attempted to remove listing {listing_id} from favorites as user {target_user_id} (owner: {listing['user_id']})",
                ip_address=request.remote_addr
            )
            flash("Cannot remove favorite for another user! (Logged)", "warning")
            return redirect(request.referrer or url_for("vuln.home"))

        # Normal remove favorite
        cursor.execute("""
            DELETE FROM favorites
            WHERE user_id = %s AND listing_id = %s
        """, (current_user.id, listing_id))
        conn.commit()

        # # Log successful removal
        # log_monitor_action(
        #     user_id=current_user.id,
        #     username=current_user.username,
        #     action_type="favorite_remove",
        #     target_id=listing_id,
        #     details=f"Removed listing {listing_id} from favorites (owner: {listing['user_id']})",
        #     ip_address=request.remote_addr
        # )

        flash("Removed from favorites!", "success")

    except Exception as e:
        flash(f"Error removing from favorites: {str(e)}", "danger")
    finally:
        conn.close()

    return redirect(request.referrer or url_for("vuln.home"))



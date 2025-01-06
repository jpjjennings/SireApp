@app.route('/assign_to_me/<int:incident_id>', methods=['POST'])
def assign_to_me(incident_id):
    if 'user_id' not in session:
        flash("You must be logged in to assign incidents.")
        return redirect(url_for('main.login'))

    responder_name = f"{session.get('first_name')} {session.get('last_name')}"

    try:
        # Get the incident using SQLAlchemy
        incident_to_update = Incident.query.get(incident_id)

        if not incident_to_update:
            flash(f"Incident {incident_id} not found.")
            return redirect(url_for('main.view_incidents'))

        # Check if the responder is already assigned
        existing_assignment = assigned_users.query.filter_by(incident_id=incident_id, responder_name=responder_name).first()
        
        if existing_assignment:
            flash(f"Incident {incident_id} is already assigned to you.")
        else:
            # Create a new assignment
            new_assignment = assigned_users(incident_id=incident_id, responder_name=responder_name)
            db.session.add(new_assignment)
            incident_to_update.Status = "In Progress"
            db.session.commit()
            flash(f"Incident {incident_id} has been assigned to you.")

    except Exception as e:
        db.session.rollback()
        flash('Failed to assign incident. Please try again.', 'danger')
        print(f"Error: {e}")

    return redirect(url_for('main.view_incidents'))
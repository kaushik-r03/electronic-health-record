from flask import Flask, render_template, request, redirect, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask import request
import pdfkit

path_to_wkhtmltopdf = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
config = pdfkit.configuration(wkhtmltopdf=path_to_wkhtmltopdf)


app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# ---------- MODELS ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(10))  # doctor / patient
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    qualification = db.Column(db.String(100))  # doctor only
    college = db.Column(db.String(200))        # doctor only
    dob = db.Column(db.String(20))
    address = db.Column(db.String(200))
    contact = db.Column(db.String(20))
    alt_contact = db.Column(db.String(20))

class Prescription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer)
    patient_id = db.Column(db.Integer)
    summary = db.Column(db.String(200))
    content = db.Column(db.Text)
    timestamp = db.Column(db.String(100))

# ---------- ROUTES ----------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    role = request.form['role']
    name = request.form['name']
    email = request.form['email']
    username = request.form['username']
    password = request.form['password']
    confirm_password = request.form['confirm-password']
    contact = request.form['contact']
    alt_contact = request.form.get('alt_contact', None)  # ✅ Safe access
    dob = request.form.get('dob', '')

    if password != confirm_password:
        flash("Passwords do not match!")
        return redirect('/')

    if User.query.filter_by(username=username).first():
        flash("Username already exists!")
        return redirect('/')

    hashed_password = generate_password_hash(password)

    if role == 'doctor':
        qualification = request.form['qualification']
        college = request.form['college']
        new_user = User(role=role, name=name, email=email, username=username,
                        password=hashed_password, qualification=qualification,
                        college=college, dob=dob, contact=contact, alt_contact=alt_contact)
    else:
        new_user = User(role=role, name=name, email=email, username=username,
                        password=hashed_password, dob=dob,
                        contact=contact, alt_contact=alt_contact)

    db.session.add(new_user)
    db.session.commit()
    flash("Signup successful. Please login.")
    return redirect('/')


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        session['username'] = user.username
        session['role'] = user.role
        return redirect('/prescription' if user.role == 'doctor' else '/prescriptions')
    else:
        flash("Invalid credentials")
        return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/myprofile')
def my_profile():
    if 'username' not in session:
        return redirect('/')
    user = User.query.filter_by(username=session['username']).first()
    referrer = request.referrer or '/'
    return render_template('profile_view.html', user=user, referrer=referrer)

@app.route('/prescription', methods=['GET', 'POST'])
def prescription():
    if 'username' not in session or session['role'] != 'doctor':
        return redirect('/')
    doctor = User.query.filter_by(username=session['username']).first()
    if request.method == 'POST':
        patient_username = request.form['patient_username']
        summary = request.form['summary']
        content = request.form['content']
        patient = User.query.filter_by(username=patient_username, role='patient').first()
        if not patient:
            flash("Patient not found.")
            return redirect('/prescription')
        new_prescription = Prescription(
            doctor_id=doctor.id,
            patient_id=patient.id,
            summary=summary,
            content=content,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M')
        )
        db.session.add(new_prescription)
        db.session.commit()
        flash("Prescription saved.")
        return redirect('/prescription')
    return render_template('prescription_editor.html')

@app.route('/prescriptions')
def prescriptions():
    if 'username' not in session or session['role'] != 'patient':
        return redirect('/')
    patient = User.query.filter_by(username=session['username']).first()
    prescriptions = Prescription.query.filter_by(patient_id=patient.id).order_by(Prescription.timestamp.desc()).all()
    return render_template('prescription_list.html', prescriptions=prescriptions)

@app.route('/doctor_prescriptions')
def doctor_prescriptions():
    if 'username' not in session or session['role'] != 'doctor':
        return redirect('/')
    doctor = User.query.filter_by(username=session['username']).first()
    prescriptions = Prescription.query.filter_by(doctor_id=doctor.id).order_by(Prescription.timestamp.desc()).all()
    return render_template('doctor_prescriptions.html', prescriptions=prescriptions)

@app.route('/check_patient', methods=['POST'])
def check_patient():
    username = request.json.get('username')
    patient = User.query.filter_by(username=username, role='patient').first()
    if patient:
        return jsonify({
            'status': 'found',
            'name': patient.name,
            'email': patient.email,
            'dob': patient.dob,
            'contact': patient.contact
        })
    return jsonify({'status': 'not_found'})

@app.route('/patient_prescriptions', methods=['POST'])
def patient_prescriptions():
    username = request.json.get('username')
    patient = User.query.filter_by(username=username, role='patient').first()
    if not patient:
        return jsonify({'status': 'not_found'})
    prescriptions = Prescription.query.filter_by(patient_id=patient.id).order_by(Prescription.timestamp.desc()).limit(5).all()
    return jsonify({
        'status': 'found',
        'prescriptions': [{
            'id': p.id,
            'summary': p.summary,
            'timestamp': p.timestamp,
            'content': p.content
        } for p in prescriptions]
    })

@app.route('/prescription/<int:presc_id>')
def view_prescription(presc_id):
    prescription = Prescription.query.get_or_404(presc_id)
    doctor = User.query.get(prescription.doctor_id)
    patient = User.query.get(prescription.patient_id)
    role = session.get('role')
    return render_template('prescription_view.html', prescription=prescription, doctor=doctor, patient=patient, role=role)

@app.route('/download/<int:presc_id>')
def download_prescription(presc_id):
    prescription = Prescription.query.get_or_404(presc_id)
    doctor = User.query.get(prescription.doctor_id)
    patient = User.query.get(prescription.patient_id)
    role = session.get('role')

    rendered = render_template('pdf_template.html', prescription=prescription, doctor=doctor, patient=patient, role=role)

    try:
        pdf = pdfkit.from_string(rendered, False, configuration=config)
        response = app.response_class(pdf, mimetype='application/pdf')
        response.headers['Content-Disposition'] = f'attachment; filename=prescription_{presc_id}.pdf'
        return response
    except Exception as e:
        return f"PDF generation failed: {e}"



# ---------- DB Setup ----------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
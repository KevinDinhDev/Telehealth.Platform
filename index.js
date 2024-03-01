const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');

const app = express();
const port = 3000;

// Create MySQL connection pool
const pool = mysql.createPool({
    connectionLimit: 10,
    host: 'localhost',
    user: 'telehealth_platform',
    password: 'telehealth_platform',
    database: 'telehealth_platform',
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'telehealth.platform.health@gmail.com',
        pass: 'luwb mkah wudi dvcu',
    },
});

// Middleware to parse JSON requests
app.use(bodyParser.json());

// Basic route
app.get('/', (req, res) => {
    res.send('Hello, Telehealth Platform!');
});

// Registering a patient
app.post('/register-patient', (req, res) => {
    const { username, password, role, firstName, lastName, patientCondition, phoneNumber, email, address, city, state, zipCode } = req.body;

    // Hash the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error('Error hashing password:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        // Use connection from pool
        pool.getConnection((connectionError, connection) => {
            if (connectionError) {
                console.error('Error getting MySQL connection:', connectionError);
                return res.status(500).json({ error: 'Internal Server Error' });
            }

            // Insert user into MySQL with hashed password and role
            const userQuery = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
            connection.query(userQuery, [username, hashedPassword, role], (userInsertError, userResult) => {
                if (userInsertError) {
                    connection.release();
                    console.error('Error registering user:', userInsertError);
                    return res.status(500).json({ error: 'Error registering user' });
                }

                // Insert patient into MySQL with additional details
                const patientQuery = 'INSERT INTO patients (user_id, first_name, last_name, patient_condition, phone_number, email, address, city, state, zip_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
                const userId = userResult.insertId;
                connection.query(patientQuery, [userId, firstName, lastName, patientCondition, phoneNumber, email, address, city, state, zipCode], (patientInsertError) => {
                    connection.release();

                    if (patientInsertError) {
                        console.error('Error registering patient:', patientInsertError);
                        return res.status(500).json({ error: 'Error registering patient' });
                    }

                    return res.json({ message: 'Patient registered successfully' });
                });
            });
        });
    });
});


// Registering a doctor
app.post('/register-doctor', (req, res) => {
    const { username, password, role, firstName, lastName, specialty, npi, email, officeNumber } = req.body;

    // Hash the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error('Error hashing password:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        // Use connection from pool
        pool.getConnection((connectionError, connection) => {
            if (connectionError) {
                console.error('Error getting MySQL connection:', connectionError);
                return res.status(500).json({ error: 'Internal Server Error' });
            }

            // Insert user into MySQL with hashed password, role
            const userQuery = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
            connection.query(userQuery, [username, hashedPassword, role], (userInsertError, userResult) => {
                if (userInsertError) {
                    connection.release();
                    console.error('Error registering user:', userInsertError);
                    return res.status(500).json({ error: 'Error registering user' });
                }

                const userId = userResult.insertId;

                // Insert doctor into MySQL with additional details
                const doctorQuery = 'INSERT INTO doctors (user_id, first_name, last_name, specialty, npi, email, office_number) VALUES (?, ?, ?, ?, ?, ?, ?)';
                connection.query(doctorQuery, [userId, firstName, lastName, specialty, npi, email, officeNumber], (doctorInsertError) => {
                    connection.release();

                    if (doctorInsertError) {
                        console.error('Error registering doctor:', doctorInsertError);
                        return res.status(500).json({ error: 'Error registering doctor' });
                    }

                    return res.json({ message: 'Doctor registered successfully' });
                });
            });
        });
    });
});


// Login route
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Use connection from pool
    pool.getConnection((connectionError, connection) => {
        if (connectionError) {
            console.error('Error getting MySQL connection:', connectionError);
            res.status(500).json({ error: 'Internal Server Error' });
            return;
        }

        // Find the user by username
        const query = 'SELECT * FROM users WHERE username = ?';
        connection.query(query, [username], (queryError, results) => {
            connection.release();

            if (queryError) {
                console.error('Error finding user:', queryError);
                res.status(500).json({ error: 'Error finding user' });
            } else if (results.length > 0) {
                // Compare passwords
                const hashedPassword = results[0].password;
                const userRole = results[0].role;

                bcrypt.compare(password, hashedPassword, (compareError, passwordMatch) => {
                    if (compareError) {
                        console.error('Error comparing passwords:', compareError);
                        res.status(500).json({ error: 'Internal Server Error' });
                    } else if (passwordMatch) {
                        // Create and send a JWT token
                        const token = jwt.sign({ username, role: userRole }, 'adminkeys');
                        console.log('Received Token:', token); // Log received token
                        res.json({ token });
                    } else {
                        res.status(401).json({ error: 'Invalid credentials' });
                    }
                });
            } else {
                res.status(401).json({ error: 'Invalid credentials' });
            }
        });
    });
});

// Protected route example (requires a valid JWT)
app.get('/dashboard', verifyToken, (req, res) => {
    console.log('Decoded Token:', req.user);
    const userRole = req.user.role;

    if (userRole === 'doctor') {
        // Doctor-specific functionality
        return res.json({ message: 'Welcome, Doctor!' });
    } else if (userRole === 'patient') {
        // Patient-specific functionality
        return res.json({ message: 'Welcome, Patient!' });
    } else {
        return res.status(403).json({ error: 'Unauthorized' });
    }
});

// Schedule appointment route
app.post('/schedule-appointment', verifyToken, (req, res) => {
    const { date, time, participants, doctorId, patientId, scheduledDate, updatedDate } = req.body;
    const userId = req.user.id; // Assuming your users table has an 'id' property

    // Validate input
    if (!date || !time || !participants || !doctorId || !patientId) {
        return res.status(400).json({ error: 'Missing required fields for scheduling appointment' });
    }

    // Use connection from pool
    pool.getConnection((connectionError, connection) => {
        if (connectionError) {
            console.error('Error getting MySQL connection:', connectionError);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        // Check for scheduling conflicts
        const conflictQuery = 'SELECT * FROM appointments WHERE date = ? AND time = ? AND doctor_id = ?';
        connection.query(conflictQuery, [date, time, doctorId], (conflictError, conflictResults) => {
            if (conflictError) {
                connection.release();
                console.error('Error checking for scheduling conflicts:', conflictError);
                return res.status(500).json({ error: 'Error checking for scheduling conflicts' });
            }

            if (conflictResults.length > 0) {
                connection.release();
                return res.status(409).json({ error: 'Scheduling conflict: Appointment already exists at this date and time' });
            }

            // No scheduling conflicts, proceed with appointment scheduling

            // Insert appointment into MySQL
            const query = 'INSERT INTO appointments (date, time, patient_id, doctor_id, scheduled_date) VALUES (?, ?, ?, ?, ?)';
            connection.query(query, [date, time, patientId, doctorId, scheduledDate], (insertError, result) => {
                if (insertError) {
                    connection.release();
                    console.error('Error scheduling appointment:', insertError);
                    return res.status(500).json({ error: 'Error scheduling appointment' });
                }

                // Associate the appointment with the patient who scheduled it
                const appointmentId = result.insertId;

                // Logic to associate the appointment with the patient in a separate table or update the users table
                const associateQuery = 'INSERT INTO user_appointments (user_id, appointment_id) VALUES (?, ?)';
                const patientUserIdQuery = 'SELECT user_id FROM patients WHERE patient_id = ?';

                connection.query(patientUserIdQuery, [patientId], (userIdError, userIdResult) => {
                    if (userIdError) {
                        connection.release();
                        console.error('Error retrieving patient user_id:', userIdError);
                        return res.status(500).json({ error: 'Error retrieving patient user_id' });
                    }

                    const patientUserId = userIdResult[0].user_id;

                    connection.query(associateQuery, [patientUserId, appointmentId], (associateError) => {
                        connection.release();

                        if (associateError) {
                            console.error('Error associating patient with appointment:', associateError);
                            return res.status(500).json({ error: 'Error associating patient with appointment' });
                        }

                        // Retrieve patient email for sending notifications
                        const emailQuery = 'SELECT email FROM patients WHERE patient_id = ?';
                        connection.query(emailQuery, [patientId], (emailError, emailResult) => {
                            if (emailError) {
                                console.error('Error retrieving patient email:', emailError);
                            } else if (emailResult.length > 0) {
                                const patientEmail = emailResult[0].email;
                                // Send email notification
                                sendAppointmentNotification(patientEmail, date, time);
                            }
                        });

                        return res.json({ message: 'Appointment scheduled successfully', appointmentId });
                    });
                });
            });
        });
    });
});





// Function to send email notification
function sendAppointmentNotification(patientEmail, date, time) {
    const mailOptions = {
        from: 'telehealth.platform.health@gmail.com',
        to: patientEmail,  // Fixing the recipient email
        subject: 'Appointment Scheduled - Telehealth Platform',
        text: `Your appointment is scheduled for ${date} at ${time}. Please log in to the Telehealth Platform for further details.`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Error sending email:', error);
        } else {
            console.log('Email sent:', info.response);
        }
    });
}

// Update appointment route
app.put('/update-appointment', verifyToken, (req, res) => {
    const { appointmentId, newTime, updatedDate } = req.body;

    // Validate input
    if (!appointmentId || !newTime || !updatedDate) {
        return res.status(400).json({ error: 'Missing required fields for updating appointment' });
    }

    // Use connection from pool
    pool.getConnection((connectionError, connection) => {
        if (connectionError) {
            console.error('Error getting MySQL connection:', connectionError);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        // Retrieve the patient's email for sending notifications
        const patientEmailQuery = 'SELECT email FROM patients WHERE user_id = (SELECT user_id FROM user_appointments WHERE appointment_id = ?)';
        connection.query(patientEmailQuery, [appointmentId], (emailError, emailResult) => {
            if (emailError) {
                connection.release();
                console.error('Error retrieving patient email:', emailError);
                return res.status(500).json({ error: 'Error retrieving patient email' });
            }

            if (emailResult.length > 0) {
                const patientEmail = emailResult[0].email;

                // Update appointment in MySQL
                const updateQuery = 'UPDATE appointments SET time = ?, updated_date = ? WHERE appointment_id = ?';
                connection.query(updateQuery, [newTime, updatedDate, appointmentId], (updateError, result) => {
                    connection.release();

                    if (updateError) {
                        console.error('Error updating appointment:', updateError);
                        return res.status(500).json({ error: 'Error updating appointment' });
                    }

                    // Send email notification
                    sendUpdateNotification(patientEmail, newTime, updatedDate);

                    return res.json({ message: 'Appointment updated successfully' });
                });
            } else {
                connection.release();
                return res.status(404).json({ error: 'Patient not found for the appointment' });
            }
        });
    });
});

// Function to send email notification for appointment updates
function sendUpdateNotification(patientEmail, newTime, updatedDate) {
    const mailOptions = {
        from: 'telehealth.platform.health@gmail.com',
        to: patientEmail,
        subject: 'Appointment Update - Telehealth Platform',
        text: `Your appointment has been updated. The new time is ${newTime} on ${updatedDate}. Log in to the Telehealth Platform for more details.`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Error sending email:', error);
        } else {
            console.log('Email sent:', info.response);
        }
    });
}



// Delete appointment route
app.delete('/delete-appointment', verifyToken, (req, res) => {
    const { appointment_id } = req.body; // Update the key to appointment_id
    const userRole = req.user.role;

    // Check user role
    if (userRole !== 'patient' && userRole !== 'doctor') {
        return res.status(403).json({ error: 'Unauthorized: Only patients and doctors can delete appointments' });
    }

    // Use connection from pool
    pool.getConnection((connectionError, connection) => {
        if (connectionError) {
            console.error('Error getting MySQL connection:', connectionError);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        // Retrieve appointment details before deletion
        const getAppointmentQuery = 'SELECT * FROM appointments WHERE appointment_id = ?';
        connection.query(getAppointmentQuery, [appointment_id], (getAppointmentError, appointmentResult) => {
            if (getAppointmentError) {
                connection.release();
                console.error('Error retrieving appointment details:', getAppointmentError);
                return res.status(500).json({ error: 'Error retrieving appointment details' });
            }

            if (appointmentResult.length === 0) {
                connection.release();
                return res.status(404).json({ error: 'Appointment not found' });
            }

            const { date, time, doctor_id, patient_id } = appointmentResult[0];

            // Delete appointment from MySQL
            const deleteQuery = 'DELETE FROM appointments WHERE appointment_id = ?';
            connection.query(deleteQuery, [appointment_id], (deleteError, result) => {
                connection.release();

                if (deleteError) {
                    console.error('Error deleting appointment:', deleteError);
                    return res.status(500).json({ error: 'Error deleting appointment' });
                }

                if (result.affectedRows === 0) {
                    // No rows were affected, meaning no appointment was found with the given ID
                    return res.status(404).json({ error: 'Appointment not found' });
                }

                console.log('Appointment deleted successfully');

                // Send email notification for appointment cancellation
                sendCancellationNotification(doctor_id, patient_id, date, time);

                return res.json({ message: 'Appointment deleted successfully' });
            });
        });
    });
});

// Function to send email notification for appointment cancellation
function sendCancellationNotification(doctorId, patientId, date, time) {
    // Retrieve doctor's and patient's email for sending notifications
    const emailQuery = 'SELECT email FROM patients WHERE user_id = ? UNION SELECT email FROM doctors WHERE user_id = ?';
    pool.query(emailQuery, [patientId, doctorId], (emailError, emailResult) => {
        if (emailError) {
            console.error('Error retrieving emails:', emailError);
            return;
        }

        const doctorEmail = emailResult[0].email;
        const patientEmail = emailResult[1].email;

        // Send email notification to both doctor and patient
        sendCancellationEmail(doctorEmail, date, time, 'Doctor');
        sendCancellationEmail(patientEmail, date, time, 'Patient');
    });
}

// Function to send email for appointment cancellation
function sendCancellationEmail(email, date, time, recipientType) {
    const mailOptions = {
        from: 'telehealth.platform.health@gmail.com',
        to: email,
        subject: `Appointment Cancellation - Telehealth Platform (${recipientType})`,
        text: `Your appointment scheduled for ${date} at ${time} has been cancelled. We apologize for any inconvenience.`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error(`Error sending ${recipientType.toLowerCase()} email:`, error);
        } else {
            console.log(`${recipientType} Email sent:`, info.response);
        }
    });
}


// Verify JWT middleware
function verifyToken(req, res, next) {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];

    if (!token) {
        return res.status(403).json({ error: 'Token not provided' });
    }

    console.log('Received Token:', token);

    jwt.verify(token, 'adminkeys', (err, decoded) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ error: 'Token has expired' });
            } else {
                console.error('JWT Verification Error:', err.message);
                return res.status(401).json({ error: 'Failed to authenticate token' });
            }
        }

        console.log('Decoded Token:', decoded); // Logs decoded payload

        req.user = decoded;
        next();
    });
}



// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});

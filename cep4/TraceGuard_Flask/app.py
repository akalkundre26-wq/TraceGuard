from flask import Flask, render_template, request, redirect, url_for, flash
import psycopg2
from psycopg2.extras import RealDictCursor
import json, os, re
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'traceguard-student-project'

# PostgreSQL URL from Render Environment Variable
DATABASE_URL = os.environ.get('DATABASE_URL')

QUESTIONS = [
'Do you use the same password on multiple websites?',
'Do you share personal information publicly online?',
'Do you accept friend/follow requests from strangers?',
'Do you post photos publicly?',
'Do you regularly check your social media privacy settings?',
'Do you click links from unknown people or websites?',
'Do you use two-factor authentication?',
'Do you delete old or unused online accounts?',
'Do you review what information about you is available online?',
'Do you think carefully before posting something online?'
]

RECOMMENDATIONS = {
1:'Use unique passwords for every site. Consider a secure password manager.',
2:'Avoid publicly posting phone numbers, home addresses, or private details.',
3:'Only accept friend/follow requests from people you know in real life.',
4:'Set your photo posts and social media accounts to private mode.',
5:'Review your privacy settings on Instagram, TikTok, and other apps monthly.',
6:'Never click suspicious or unknown links to prevent phishing attacks.',
7:'Turn on Two-Factor Authentication (2FA) on all your primary accounts.',
8:"Delete unused accounts so old personal data isn't exposed in data leaks.",
9:'Search your name online periodically to see what public information exists.',
10:'Remember that deleted posts can still be saved or screenshotted by others.'
}

RISKY_YES = {1,2,3,4,6}

TIPS = [
('🔐','Strong Passwords','Use unique and strong passwords for different accounts. Avoid using simple passwords like “123456” or your birthday.'),
('🛡️','Two-Factor Authentication','Enable 2FA whenever it is available. It adds an extra layer of security beyond just your password.'),
('🔒','Social Media Privacy','Review who can see your posts, profile, photos, and personal information. Set your accounts to private mode.'),
('⚠️','Avoid Phishing Links','Do not click suspicious links or attachments from unknown sources or unexpected emails and messages.'),
('❗','Protect Personal Information','Avoid publicly sharing phone numbers, home addresses, passwords, school details, or sensitive IDs online.'),
('↻','Manage Old Accounts','Delete accounts and apps that you no longer use so old data doesn’t remain exposed in security breaches.'),
('✨','Think Before Posting','Remember that online posts, photos, and comments can remain accessible forever, even if deleted.')
]


def detect_metadata(user_agent):
    ua = user_agent or ''
    low = ua.lower()

    if re.search(r'tablet|ipad|playbook|silk', low):
        device = 'Tablet'
    elif re.search(r'mobi|iphone|ipod|android', low):
        device = 'Mobile'
    elif ua:
        device = 'Desktop'
    else:
        device = 'Unknown'

    if 'edg/' in low:
        browser = 'Microsoft Edge'
    elif 'opr/' in low:
        browser = 'Opera'
    elif 'firefox/' in low:
        browser = 'Firefox'
    elif 'chrome/' in low and 'edg/' not in low:
        browser = 'Google Chrome'
    elif 'safari/' in low and 'chrome/' not in low and 'android' not in low:
        browser = 'Safari'
    else:
        browser = 'Unknown browser'

    if 'windows' in low:
        os_name = 'Windows'
    elif 'android' in low:
        os_name = 'Android'
    elif re.search(r'iphone|ipad|ipod', low):
        os_name = 'iOS'
    elif 'mac os x' in low:
        os_name = 'macOS'
    elif 'linux' in low:
        os_name = 'Linux'
    else:
        os_name = 'Unknown OS'

    return device, browser, os_name


# PostgreSQL connection
def connect():
    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=RealDictCursor
    )


# Create tables
def init_db():
    c = connect()
    cur = c.cursor()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS audits(
            id SERIAL PRIMARY KEY,
            student_name TEXT,
            answers TEXT NOT NULL,
            device_type TEXT,
            browser TEXT,
            operating_system TEXT,
            location TEXT,
            score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            recommendations TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS feedback(
            id SERIAL PRIMARY KEY,
            audit_id INTEGER NOT NULL,
            rating INTEGER NOT NULL,
            website_experience TEXT NOT NULL,
            comment TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(audit_id)
                REFERENCES audits(id)
                ON DELETE CASCADE
        )
    ''')

    c.commit()
    cur.close()
    c.close()


def calc(answers):
    risky = []

    for i, a in enumerate(answers, 1):
        if a == (i in RISKY_YES):
            risky.append(i)

    score = len(risky)

    level = 'Low' if score <= 2 else ('Medium' if score <= 5 else 'High')

    rec = [RECOMMENDATIONS[i] for i in risky] or [
        'Keep up the great habits and stay informed about cybersecurity!'
    ]

    return score, level, rec


@app.route('/', methods=['GET','POST'])
def audit():

    result = None

    if request.method == 'POST':

        if request.form.get('action') == 'audit':

            answers = []

            for i in range(1,11):

                v = request.form.get(f'q{i}')

                if v not in ('yes','no'):
                    flash('Please answer all 10 questions.','error')

                    return render_template(
                        'audit.html',
                        questions=QUESTIONS,
                        tips=TIPS,
                        result=None
                    )

                answers.append(v == 'yes')

            score, level, recs = calc(answers)

            device_type, browser, operating_system = detect_metadata(
                request.headers.get('User-Agent','')
            )

            c = connect()
            cur = c.cursor()

            cur.execute('''
                INSERT INTO audits(
                    student_name,
                    answers,
                    device_type,
                    browser,
                    operating_system,
                    location,
                    score,
                    risk_level,
                    recommendations,
                    created_at
                )
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING id
            ''', (
                request.form.get('student_name','').strip() or None,
                json.dumps(answers),
                device_type,
                browser,
                operating_system,
                request.form.get('location','').strip() or None,
                score,
                level,
                json.dumps(recs),
                datetime.now().isoformat(timespec='seconds')
            ))

            audit_id = cur.fetchone()['id']

            c.commit()
            cur.close()
            c.close()

            result = {
                'id': audit_id,
                'score': score,
                'risk_level': level,
                'recommendations': recs
            }


        elif request.form.get('action') == 'feedback':

            audit_id = int(request.form['audit_id'])
            rating = request.form.get('rating')
            exp = request.form.get('experience')

            if rating and exp:

                c = connect()
                cur = c.cursor()

                cur.execute('''
                    INSERT INTO feedback(
                        audit_id,
                        rating,
                        website_experience,
                        comment,
                        created_at
                    )
                    VALUES(%s,%s,%s,%s,%s)
                ''', (
                    audit_id,
                    int(rating),
                    exp,
                    request.form.get('comment','').strip() or None,
                    datetime.now().isoformat(timespec='seconds')
                ))

                c.commit()
                cur.close()
                c.close()

                flash(
                    'Thanks for your feedback. Your response has been saved.',
                    'success'
                )

            return redirect(url_for('records'))

    return render_template(
        'audit.html',
        questions=QUESTIONS,
        tips=TIPS,
        result=result
    )


@app.route('/records')
def records():

    c = connect()
    cur = c.cursor()

    cur.execute('SELECT * FROM audits ORDER BY id DESC')
    rows = cur.fetchall()

    cur.execute('SELECT * FROM feedback ORDER BY id DESC')
    feedback_rows = cur.fetchall()

    feedback = {
        r['audit_id']: r
        for r in feedback_rows
    }

    cur.close()
    c.close()

    audits = []

    q_correct = [0] * 10
    q_wrong = [0] * 10

    for r in rows:

        d = dict(r)

        d['answers'] = json.loads(d['answers'])
        d['recommendations'] = json.loads(d['recommendations'])
        d['feedback'] = feedback.get(d['id'])

        audits.append(d)

        for i, a in enumerate(d['answers'], 1):

            risky = (a == (i in RISKY_YES))

            q_wrong[i-1] += int(risky)
            q_correct[i-1] += int(not risky)

    n = len(audits)

    total_risky = sum(a['score'] for a in audits)
    total_answers = n * 10

    stats = {
        'total': n,
        'avg': round(total_risky/n,1) if n else 0,
        'correct': total_answers-total_risky,
        'wrong': total_risky,

        'low': sum(a['risk_level']=='Low' for a in audits),
        'medium': sum(a['risk_level']=='Medium' for a in audits),
        'high': sum(a['risk_level']=='High' for a in audits),

        'latest':
            audits[0]['created_at']
            if audits
            else 'No submissions yet'
    }

    return render_template(
        'records.html',
        audits=audits,
        stats=stats,
        questions=QUESTIONS,
        q_correct=q_correct,
        q_wrong=q_wrong
    )


@app.post('/delete/<int:audit_id>')
def delete(audit_id):

    c = connect()
    cur = c.cursor()

    cur.execute(
        'DELETE FROM feedback WHERE audit_id=%s',
        (audit_id,)
    )

    cur.execute(
        'DELETE FROM audits WHERE id=%s',
        (audit_id,)
    )

    c.commit()
    cur.close()
    c.close()

    flash(
        'Record deleted. The saved audit has been removed.',
        'success'
    )

    return redirect(url_for('records'))


# Create PostgreSQL tables when the app starts
init_db()


if __name__ == '__main__':
    app.run(
        debug=True,
        host='127.0.0.1',
        port=5000
    )
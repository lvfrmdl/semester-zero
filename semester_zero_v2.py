
"""
SEMESTER ZERO v2.0
Role-based, terminal attendance management system.
Storage: interconnected CSV files | Charts: Matplotlib
Place this file in the same folder as the extracted sample CSV files.
Demo password for all sample accounts: Semester@123
"""

import csv
import os
import hashlib
import hmac
from datetime import datetime, date
from collections import defaultdict

APP_NAME = "SEMESTER ZERO"
FILES = {
    "users": "users.csv",
    "students": "students.csv",
    "teachers": "teachers.csv",
    "subjects": "subjects.csv",
    "enrollments": "enrollments.csv",
    "sessions": "attendance_sessions.csv",
    "records": "attendance_records.csv",
    "logs": "audit_logs.csv",
}
THRESHOLD = 75.0
ORANGE_LIMIT = 80.0
PASSWORD_ITERATIONS = 120000

try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


# ======================== CSV STORAGE LAYER ========================

HEADERS = {
    "users": ["user_id", "password_hash", "salt", "role", "linked_id", "status"],
    "students": ["student_id", "student_name", "section", "semester", "department", "email"],
    "teachers": ["teacher_id", "teacher_name", "email", "department"],
    "subjects": ["subject_code", "subject_name", "teacher_id", "sections", "semester"],
    "enrollments": ["student_id", "subject_code", "academic_term", "section"],
    "sessions": ["session_id", "subject_code", "teacher_id", "session_date", "academic_term", "department"],
    "records": ["record_id", "session_id", "student_id", "subject_code", "status", "remarks"],
    "logs": ["log_id", "user_id", "action", "details", "timestamp"],
}


def read_csv(kind):
    path = FILES[kind]

    if not os.path.exists(path):
        write_csv(kind, [])

    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def write_csv(kind, rows):
    with open(FILES[kind], "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=HEADERS[kind])
        writer.writeheader()
        writer.writerows(rows)


def append_csv(kind, row):
    if not os.path.exists(FILES[kind]):
        write_csv(kind, [])

    with open(FILES[kind], "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=HEADERS[kind])
        writer.writerow(row)


def ensure_files():
    for kind in FILES:
        if not os.path.exists(FILES[kind]):
            write_csv(kind, [])


def next_id(kind, prefix, width=6):
    rows = read_csv(kind)
    field = HEADERS[kind][0]
    numbers = []

    for row in rows:
        value = row.get(field, "")

        if value.startswith(prefix):
            try:
                numbers.append(int(value[len(prefix):]))
            except ValueError:
                pass

    return prefix + str(max(numbers, default=0) + 1).zfill(width)


def log_action(user_id, action, details):
    append_csv("logs", {
        "log_id": next_id("logs", "LOG"),
        "user_id": user_id,
        "action": action,
        "details": details,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })


# ======================== TERMINAL UTILITIES ========================

def line(char="=", width=76):
    print(char * width)


def heading(title):
    print()
    line()
    print("  " + title.upper())
    line()


def pause():
    input("\nPress Enter to continue...")


def ask(prompt, allow_blank=False):
    while True:
        value = input(prompt).strip()

        if value or allow_blank:
            return value

        print("This field cannot be blank.")


def ask_int(prompt, minimum=0, maximum=None):
    while True:
        try:
            value = int(input(prompt).strip())

            if value < minimum or (
                maximum is not None and value > maximum
            ):
                print("Enter a value between {} and {}.".format(
                    minimum,
                    maximum if maximum is not None else "infinity"
                ))
            else:
                return value

        except ValueError:
            print("Please enter a whole number.")


def ask_yes_no(prompt):
    while True:
        value = input(prompt + " (y/n): ").strip().lower()

        if value in ("y", "yes"):
            return True

        if value in ("n", "no"):
            return False

        print("Enter y or n.")


# ======================== ATTENDANCE CALCULATIONS ========================

def pct(attended, total):
    return (attended / total * 100) if total else 0.0


def status_for(value):
    if value < THRESHOLD:
        return "CRITICAL"

    if value < ORANGE_LIMIT:
        return "WARNING"

    return "SAFE"


def recovery_needed(attended, total, target=THRESHOLD):
    if total == 0 or pct(attended, total) >= target:
        return 0

    return max(
        0,
        int(
            (target * total / 100 - attended) /
            (1 - target / 100) + 0.999999
        )
    )


def max_bunks(attended, total, target=THRESHOLD):
    if total == 0 or pct(attended, total) < target:
        return 0

    return max(0, int(attended * 100 / target - total + 1e-9))


# ======================== AUTHENTICATION ========================

def password_digest(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_ITERATIONS
    ).hex()


def authenticate():
    heading("Secure Login")
    print("Sign in using your university ID.")

    for _ in range(3):
        user_id = ask("User ID: ")
        password = ask("Password: ")

        user = next(
            (
                u for u in read_csv("users")
                if u["user_id"].casefold() == user_id.casefold()
            ),
            None
        )

        if user and user.get("status", "active").lower() == "active":
            candidate = password_digest(password, user["salt"])

            if hmac.compare_digest(candidate, user["password_hash"]):
                log_action(user["user_id"], "LOGIN", "Successful login")
                return user

        print("Invalid credentials or inactive account. Try again.\n")

    print("Too many failed attempts.")
    return None


# ======================== DATABASE LOOKUPS ========================

def student_by_id(student_id):
    return next(
        (
            s for s in read_csv("students")
            if s["student_id"].casefold() == student_id.casefold()
        ),
        None
    )


def teacher_by_id(teacher_id):
    return next(
        (
            t for t in read_csv("teachers")
            if t["teacher_id"].casefold() == teacher_id.casefold()
        ),
        None
    )


def subject_by_code(code):
    return next(
        (
            s for s in read_csv("subjects")
            if s["subject_code"].casefold() == code.casefold()
        ),
        None
    )


def subject_name(code):
    subject = subject_by_code(code)
    return subject["subject_name"] if subject else code


def student_subject_summary(student_id):
    enrollments = [
        e for e in read_csv("enrollments")
        if e["student_id"].casefold() == student_id.casefold()
    ]

    records = read_csv("records")
    sessions = {
        s["session_id"]: s for s in read_csv("sessions")
    }

    summary = []

    for enrollment in enrollments:
        code = enrollment["subject_code"]

        relevant = [
            r for r in records
            if r["student_id"] == student_id
            and r["subject_code"] == code
            and r["session_id"] in sessions
        ]

        total = len(relevant)

        attended = sum(
            1 for r in relevant
            if r["status"].lower() == "present"
        )

        summary.append({
            "code": code,
            "subject": subject_name(code),
            "total": total,
            "attended": attended,
            "percentage": pct(attended, total),
        })

    return summary


def students_for_subject(code, term=None):
    ids = {
        e["student_id"]
        for e in read_csv("enrollments")
        if e["subject_code"] == code
        and (term is None or e["academic_term"] == term)
    }

    return [
        s for s in read_csv("students")
        if s["student_id"] in ids
    ]


def teacher_subjects(teacher_id):
    return [
        s for s in read_csv("subjects")
        if s["teacher_id"] == teacher_id
    ]


def print_subject_table(items):
    if not items:
        print("No subject records found.")
        return

    line("-")

    print("{:<12} {:<27} {:>8} {:>8} {:>10} {:>11}".format(
        "CODE",
        "SUBJECT",
        "ATTENDED",
        "TOTAL",
        "PERCENT",
        "STATUS"
    ))

    line("-")

    for item in items:
        print("{:<12} {:<27} {:>8} {:>8} {:>9.2f}% {:>11}".format(
            item["code"],
            item["subject"][:27],
            item["attended"],
            item["total"],
            item["percentage"],
            status_for(item["percentage"])
        ))

    line("-")


# ======================== STUDENT PORTAL ========================

def student_dashboard(user):
    student = student_by_id(user["linked_id"])

    if not student:
        print("Student profile not found.")
        return

    items = student_subject_summary(student["student_id"])

    total = sum(x["total"] for x in items)
    attended = sum(x["attended"] for x in items)
    overall = pct(attended, total)

    heading("Student Dashboard")

    print("STUDENT : {} ({})".format(
        student["student_name"],
        student["student_id"]
    ))

    print("SECTION : {} | SEMESTER: {}".format(
        student["section"],
        student["semester"]
    ))

    print("OVERALL : {:.2f}% | ATTENDED: {}/{}".format(
        overall, attended, total
    ))

    print("SUBJECTS: {} | BELOW 75%: {}".format(
        len(items),
        sum(1 for x in items if x["percentage"] < THRESHOLD)
    ))

    print_subject_table(items)

    risky = sorted(
        [x for x in items if x["percentage"] < THRESHOLD],
        key=lambda x: x["percentage"]
    )

    if risky:
        print("\nACTION REQUIRED")

        for x in risky:
            print(
                " - {}: attend {} consecutive classes to reach 75%.".format(
                    x["subject"],
                    recovery_needed(x["attended"], x["total"])
                )
            )


def student_risk(user):
    heading("Subject Risk Analysis")

    items = student_subject_summary(user["linked_id"])

    risky = sorted(
        [x for x in items if x["percentage"] < THRESHOLD],
        key=lambda x: x["percentage"]
    )

    if not risky:
        print("No subjects are currently below the attendance threshold.")
        return

    for x in risky:
        print(
            "{} | {:.2f}% | {:.2f} points below target | "
            "{} classes to recover".format(
                x["subject"],
                x["percentage"],
                THRESHOLD - x["percentage"],
                recovery_needed(x["attended"], x["total"])
            )
        )


def student_chart(user):
    heading("Attendance Chart")

    if not MATPLOTLIB_AVAILABLE:
        print("Install Matplotlib using: py -m pip install matplotlib")
        return

    items = student_subject_summary(user["linked_id"])

    if not items:
        print("No attendance data available.")
        return

    names = [x["subject"] for x in items]
    values = [x["percentage"] for x in items]

    colors = [
        "red" if v < 75 else "orange" if v < 80 else "green"
        for v in values
    ]

    fig, ax = plt.subplots(figsize=(11, 6))

    bars = ax.bar(
        names,
        values,
        color=colors,
        edgecolor="black",
        alpha=.85
    )

    ax.axhline(
        75,
        color="crimson",
        linestyle="--",
        linewidth=2,
        label="75% threshold"
    )

    ax.set_ylim(0, 105)
    ax.set_ylabel("Attendance (%)")
    ax.set_title("SEMESTER ZERO | {}".format(user["linked_id"]))
    ax.grid(axis="y", linestyle=":", alpha=.35)
    ax.legend()

    plt.xticks(rotation=25, ha="right")

    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width()/2,
            value + 1,
            "{:.1f}%".format(value),
            ha="center",
            fontsize=8
        )

    fig.tight_layout()
    plt.show()


def student_bunk_calculator(user):
    heading("Bunk Calculator")

    items = student_subject_summary(user["linked_id"])
    print_subject_table(items)

    code = ask("Subject code: ").upper()

    item = next(
        (x for x in items if x["code"].upper() == code),
        None
    )

    if not item:
        print("Subject not found.")
        return

    print("Current attendance: {:.2f}%".format(item["percentage"]))

    if item["percentage"] < THRESHOLD:
        print(
            "You need to attend {} consecutive classes to recover to 75%."
            .format(
                recovery_needed(item["attended"], item["total"])
            )
        )
    else:
        print(
            "Maximum future classes you can miss and remain at/above 75%: {}"
            .format(
                max_bunks(item["attended"], item["total"])
            )
        )


def student_recovery_planner(user):
    heading("Recovery Planner")

    risky = [
        x for x in student_subject_summary(user["linked_id"])
        if x["percentage"] < THRESHOLD
    ]

    if not risky:
        print("All subjects are at or above 75%.")
        return

    for x in sorted(risky, key=lambda a: a["percentage"]):
        needed = recovery_needed(x["attended"], x["total"])

        print("\n{} ({:.2f}%)".format(
            x["subject"],
            x["percentage"]
        ))

        print("Plan: attend the next {} classes consecutively.".format(
            needed
        ))


def student_what_if(user):
    heading("What-if Simulator")

    items = student_subject_summary(user["linked_id"])
    print_subject_table(items)

    code = ask("Subject code: ").upper()

    item = next(
        (x for x in items if x["code"].upper() == code),
        None
    )

    if not item:
        print("Subject not found.")
        return

    print("1. Attend future classes")
    print("2. Miss future classes")

    choice = ask("Choose scenario: ")

    if choice not in ("1", "2"):
        print("Invalid scenario.")
        return

    count = ask_int("Number of future classes: ", 0)

    attended = item["attended"] + (
        count if choice == "1" else 0
    )

    total = item["total"] + count
    projected = pct(attended, total)

    print("\nSIMULATION — NOT SAVED")

    print("Current: {:.2f}% | Projected: {:.2f}% | Status: {}".format(
        item["percentage"],
        projected,
        status_for(projected)
    ))


def student_report(user):
    heading("Personal Attendance Report")

    student = student_by_id(user["linked_id"])
    items = student_subject_summary(user["linked_id"])

    filename = "{}_attendance_report.csv".format(
        user["linked_id"]
    )

    fields = [
        "student_id",
        "student_name",
        "subject_code",
        "subject_name",
        "classes_attended",
        "classes_conducted",
        "attendance_percentage",
        "status"
    ]

    with open(filename, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for x in items:
            writer.writerow({
                "student_id": student["student_id"],
                "student_name": student["student_name"],
                "subject_code": x["code"],
                "subject_name": x["subject"],
                "classes_attended": x["attended"],
                "classes_conducted": x["total"],
                "attendance_percentage": "{:.2f}".format(x["percentage"]),
                "status": status_for(x["percentage"]),
            })

    print("Report exported: {}".format(os.path.abspath(filename)))


def student_portal(user):
    actions = {
        "1": ("Attendance Dashboard", lambda: student_dashboard(user)),
        "2": ("Subject Risk Analysis", lambda: student_risk(user)),
        "3": ("Attendance Chart", lambda: student_chart(user)),
        "4": ("Bunk Calculator", lambda: student_bunk_calculator(user)),
        "5": ("Recovery Planner", lambda: student_recovery_planner(user)),
        "6": ("What-if Simulator", lambda: student_what_if(user)),
        "7": ("Export Personal Report", lambda: student_report(user)),
    }

    while True:
        heading("Student Portal")

        for key, (label, _) in actions.items():
            print("[{}] {}".format(key, label))

        print("[0] Logout")

        choice = ask("Select option: ")

        if choice == "0":
            return

        if choice in actions:
            actions[choice][1]()
        else:
            print("Invalid option.")

        pause()


# ======================== TEACHER PORTAL ========================

def teacher_dashboard(user):
    heading("Teacher Overview")

    assigned = teacher_subjects(user["linked_id"])

    print("Assigned subjects: {}".format(len(assigned)))

    for sub in assigned:
        roster = students_for_subject(sub["subject_code"])

        sessions = [
            s for s in read_csv("sessions")
            if s["subject_code"] == sub["subject_code"]
        ]

        records = [
            r for r in read_csv("records")
            if r["subject_code"] == sub["subject_code"]
        ]

        present = sum(
            1 for r in records if r["status"] == "Present"
        )

        average = pct(present, len(records))

        print("\n{} | {}".format(
            sub["subject_code"],
            sub["subject_name"]
        ))

        print(
            "Students: {} | Sessions: {} | "
            "Class attendance average: {:.2f}%".format(
                len(roster), len(sessions), average
            )
        )


def teacher_roster(user):
    heading("Class Attendance Overview")

    assigned = teacher_subjects(user["linked_id"])

    if not assigned:
        print("No subjects assigned.")
        return

    for i, sub in enumerate(assigned, 1):
        print("[{}] {} - {}".format(
            i,
            sub["subject_code"],
            sub["subject_name"]
        ))

    choice = ask_int("Choose subject number: ", 1, len(assigned))
    sub = assigned[choice - 1]
    code = sub["subject_code"]

    records = read_csv("records")

    sessions = {
        s["session_id"]
        for s in read_csv("sessions")
        if s["subject_code"] == code
    }

    print("\n{} | {}".format(code, sub["subject_name"]))

    print("{:<13} {:<24} {:>9} {:>9} {:>10}".format(
        "STUDENT ID", "NAME", "PRESENT", "TOTAL", "ATTENDANCE"
    ))

    for student in students_for_subject(code):
        own = [
            r for r in records
            if r["student_id"] == student["student_id"]
            and r["session_id"] in sessions
        ]

        total = len(own)

        present = sum(
            1 for r in own if r["status"] == "Present"
        )

        print("{:<13} {:<24} {:>9} {:>9} {:>9.2f}%".format(
            student["student_id"],
            student["student_name"][:24],
            present,
            total,
            pct(present, total)
        ))


def teacher_mark_attendance(user):
    heading("Create Attendance Session")

    assigned = teacher_subjects(user["linked_id"])

    if not assigned:
        print("No subjects assigned.")
        return

    for i, sub in enumerate(assigned, 1):
        print("[{}] {} - {}".format(
            i,
            sub["subject_code"],
            sub["subject_name"]
        ))

    choice = ask_int("Choose subject: ", 1, len(assigned))
    sub = assigned[choice - 1]

    session_date = ask(
        "Session date (YYYY-MM-DD, Enter for today): ",
        True
    )

    if not session_date:
        session_date = date.today().isoformat()

    try:
        datetime.strptime(session_date, "%Y-%m-%d")
    except ValueError:
        print("Invalid date format.")
        return

    term = ask("Academic term (e.g. 2026-ODD): ")

    existing = [
        s for s in read_csv("sessions")
        if s["subject_code"] == sub["subject_code"]
        and s["session_date"] == session_date
        and s["academic_term"] == term
    ]

    if existing:
        print("A session already exists for this subject on that date.")
        return

    roster = students_for_subject(sub["subject_code"], term)

    if not roster:
        print("No enrolled students found for this subject and term.")
        return

    session_id = next_id("sessions", "SES", 4)

    append_csv("sessions", {
        "session_id": session_id,
        "subject_code": sub["subject_code"],
        "teacher_id": user["linked_id"],
        "session_date": session_date,
        "academic_term": term,
        "department": "CSE",
    })

    present_count = 0

    for student in roster:
        while True:
            status = input(
                "{} ({}) [P/A/L]: ".format(
                    student["student_name"],
                    student["student_id"]
                )
            ).strip().upper()

            if status in ("P", "A", "L"):
                break

            print("Enter P, A or L.")

        status_name = {
            "P": "Present",
            "A": "Absent",
            "L": "Leave"
        }[status]

        if status_name == "Present":
            present_count += 1

        append_csv("records", {
            "record_id": next_id("records", "ATT"),
            "session_id": session_id,
            "student_id": student["student_id"],
            "subject_code": sub["subject_code"],
            "status": status_name,
            "remarks": "",
        })

    log_action(
        user["user_id"],
        "MARK_ATTENDANCE",
        "{} on {} ({} students)".format(
            sub["subject_code"], session_date, len(roster)
        )
    )

    print("\nSession {} saved. Present: {}/{}".format(
        session_id, present_count, len(roster)
    ))


def teacher_defaulters(user):
    heading("Defaulter List")

    all_records = read_csv("records")
    all_sessions = read_csv("sessions")

    for sub in teacher_subjects(user["linked_id"]):
        code = sub["subject_code"]

        sessions = {
            s["session_id"]
            for s in all_sessions
            if s["subject_code"] == code
        }

        print("\n{} - {}".format(code, sub["subject_name"]))

        found = False

        for student in students_for_subject(code):
            own = [
                r for r in all_records
                if r["student_id"] == student["student_id"]
                and r["session_id"] in sessions
            ]

            total = len(own)

            attended = sum(
                1 for r in own if r["status"] == "Present"
            )

            value = pct(attended, total)

            if total and value < THRESHOLD:
                found = True

                print(
                    "  {} | {} | {:.2f}% | {} classes to recover".format(
                        student["student_id"],
                        student["student_name"],
                        value,
                        recovery_needed(attended, total)
                    )
                )

        if not found:
            print("  No defaulters in recorded sessions.")


def teacher_portal(user):
    actions = {
        "1": ("Teacher Overview", lambda: teacher_dashboard(user)),
        "2": ("Class Attendance Overview", lambda: teacher_roster(user)),
        "3": ("Mark Attendance / Create Session", lambda: teacher_mark_attendance(user)),
        "4": ("Defaulter List", lambda: teacher_defaulters(user)),
    }

    while True:
        heading("Teacher Portal")

        for key, (label, _) in actions.items():
            print("[{}] {}".format(key, label))

        print("[0] Logout")

        choice = ask("Select option: ")

        if choice == "0":
            return

        if choice in actions:
            actions[choice][1]()
        else:
            print("Invalid option.")

        pause()


# ======================== ADMINISTRATOR PORTAL ========================

def admin_overview():
    heading("Institution Overview")

    students = read_csv("students")
    teachers = read_csv("teachers")
    subjects = read_csv("subjects")
    sessions = read_csv("sessions")
    records = read_csv("records")

    present = sum(
        1 for r in records if r["status"] == "Present"
    )

    print("Students: {} | Teachers: {} | Subjects: {}".format(
        len(students), len(teachers), len(subjects)
    ))

    print("Attendance sessions: {} | Attendance records: {}".format(
        len(sessions), len(records)
    ))

    print("Institution-wide recorded attendance: {:.2f}%".format(
        pct(present, len(records))
    ))

    print("\nSUBJECT-WISE PERFORMANCE")

    for sub in subjects:
        own = [
            r for r in records
            if r["subject_code"] == sub["subject_code"]
        ]

        p = sum(1 for r in own if r["status"] == "Present")

        print("{:<12} {:<27} {:>8.2f}%  ({} records)".format(
            sub["subject_code"],
            sub["subject_name"][:27],
            pct(p, len(own)),
            len(own)
        ))


def admin_search():
    heading("Search All Records")

    query = ask(
        "Search student ID, name, teacher, subject or code: "
    ).casefold()

    found = False

    for s in read_csv("students"):
        if (
            query in s["student_id"].casefold()
            or query in s["student_name"].casefold()
        ):
            print(
                "STUDENT | {} | {} | {}".format(
                    s["student_id"], s["student_name"], s["section"]
                )
            )
            found = True

    for t in read_csv("teachers"):
        if (
            query in t["teacher_id"].casefold()
            or query in t["teacher_name"].casefold()
        ):
            print(
                "TEACHER | {} | {}".format(
                    t["teacher_id"], t["teacher_name"]
                )
            )
            found = True

    for sub in read_csv("subjects"):
        if (
            query in sub["subject_code"].casefold()
            or query in sub["subject_name"].casefold()
        ):
            print(
                "SUBJECT | {} | {} | Teacher: {}".format(
                    sub["subject_code"],
                    sub["subject_name"],
                    sub["teacher_id"]
                )
            )
            found = True

    if not found:
        print("No matching records.")


def admin_add_student():
    heading("Add Student")

    student_id = ask("Student ID: ").upper()

    if student_by_id(student_id):
        print("That student ID already exists.")
        return

    name = ask("Full name: ")
    section = ask("Section: ").upper()
    semester = ask("Semester: ")
    department = ask("Department: ")
    email = ask("Email: ")

    append_csv("students", {
        "student_id": student_id,
        "student_name": name,
        "section": section,
        "semester": semester,
        "department": department,
        "email": email
    })

    password = ask("Set temporary password: ")
    salt = os.urandom(16).hex()

    append_csv("users", {
        "user_id": student_id,
        "password_hash": password_digest(password, salt),
        "salt": salt,
        "role": "student",
        "linked_id": student_id,
        "status": "active"
    })

    log_action("ADMIN", "ADD_STUDENT", student_id)

    print("Student and login account created.")


def admin_add_teacher():
    heading("Add Teacher")

    teacher_id = ask("Teacher ID: ").upper()

    if teacher_by_id(teacher_id):
        print("That teacher ID already exists.")
        return

    name = ask("Full name: ")
    email = ask("Email: ")
    department = ask("Department: ")

    append_csv("teachers", {
        "teacher_id": teacher_id,
        "teacher_name": name,
        "email": email,
        "department": department
    })

    password = ask("Set temporary password: ")
    salt = os.urandom(16).hex()

    append_csv("users", {
        "user_id": teacher_id,
        "password_hash": password_digest(password, salt),
        "salt": salt,
        "role": "teacher",
        "linked_id": teacher_id,
        "status": "active"
    })

    log_action("ADMIN", "ADD_TEACHER", teacher_id)

    print("Teacher and login account created.")


def admin_add_subject():
    heading("Add Subject")

    code = ask("Subject code: ").upper()

    if subject_by_code(code):
        print("That subject code already exists.")
        return

    name = ask("Subject name: ")
    teacher_id = ask("Assigned teacher ID: ").upper()

    if not teacher_by_id(teacher_id):
        print("Teacher not found.")
        return

    sections = ask(
        "Sections (semicolon-separated, e.g. CSE-A;CSE-B): "
    ).upper()

    semester = ask("Semester: ")

    append_csv("subjects", {
        "subject_code": code,
        "subject_name": name,
        "teacher_id": teacher_id,
        "sections": sections,
        "semester": semester
    })

    term = ask("Academic term for enrolment (e.g. 2026-ODD): ")

    count = 0
    section_list = [x.strip() for x in sections.split(";")]

    for student in read_csv("students"):
        if (
            student["section"] in section_list
            and student["semester"] == semester
        ):
            append_csv("enrollments", {
                "student_id": student["student_id"],
                "subject_code": code,
                "academic_term": term,
                "section": student["section"]
            })

            count += 1

    log_action(
        "ADMIN",
        "ADD_SUBJECT",
        "{} assigned to {}".format(code, teacher_id)
    )

    print("Subject created. {} student(s) enrolled.".format(count))


def admin_manage_users():
    heading("User Account Management")

    users = read_csv("users")

    for u in users:
        print("{:<14} {:<10} {:<14} {}".format(
            u["user_id"],
            u["role"],
            u["status"],
            u["linked_id"]
        ))

    user_id = ask(
        "Enter user ID to activate/deactivate (Enter to cancel): ",
        True
    )

    if not user_id:
        return

    target = next(
        (
            u for u in users
            if u["user_id"].casefold() == user_id.casefold()
        ),
        None
    )

    if not target:
        print("User not found.")
        return

    if target["role"] == "admin":
        print("Admin account status cannot be changed from this menu.")
        return

    target["status"] = (
        "inactive" if target["status"] == "active" else "active"
    )

    write_csv("users", users)

    log_action(
        "ADMIN",
        "CHANGE_USER_STATUS",
        "{} -> {}".format(user_id, target["status"])
    )

    print("Account status changed to {}.".format(target["status"]))


def admin_all_students():
    heading("Student Directory")

    print("{:<14} {:<25} {:<12} {:<9} {}".format(
        "STUDENT ID",
        "NAME",
        "SECTION",
        "SEMESTER",
        "DEPARTMENT"
    ))

    for s in read_csv("students"):
        print("{:<14} {:<25} {:<12} {:<9} {}".format(
            s["student_id"],
            s["student_name"][:25],
            s["section"],
            s["semester"],
            s["department"]
        ))


def admin_export():
    heading("Export Institutional Report")

    records = read_csv("records")

    sessions = {
        s["session_id"]: s
        for s in read_csv("sessions")
    }

    students = {
        s["student_id"]: s
        for s in read_csv("students")
    }

    filename = ask(
        "Filename (Enter for institutional_attendance_report.csv): ",
        True
    )

    if not filename:
        filename = "institutional_attendance_report.csv"

    if not filename.lower().endswith(".csv"):
        filename += ".csv"

    fields = [
        "student_id",
        "student_name",
        "section",
        "subject_code",
        "subject_name",
        "classes_attended",
        "classes_conducted",
        "attendance_percentage",
        "status"
    ]

    grouped = defaultdict(list)

    for r in records:
        if r["session_id"] in sessions:
            grouped[
                (r["student_id"], r["subject_code"])
            ].append(r)

    with open(filename, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for (student_id, code), group in grouped.items():
            student = students.get(student_id, {})

            attended = sum(
                1 for r in group if r["status"] == "Present"
            )

            total = len(group)
            value = pct(attended, total)

            writer.writerow({
                "student_id": student_id,
                "student_name": student.get("student_name", ""),
                "section": student.get("section", ""),
                "subject_code": code,
                "subject_name": subject_name(code),
                "classes_attended": attended,
                "classes_conducted": total,
                "attendance_percentage": "{:.2f}".format(value),
                "status": status_for(value),
            })

    print(
        "{} rows exported to {}".format(
            len(grouped), os.path.abspath(filename)
        )
    )


def admin_audit_logs():
    heading("Audit Log")

    logs = read_csv("logs")

    if not logs:
        print("No activity recorded yet.")
        return

    for item in logs[-40:]:
        print("{} | {:<12} | {:<20} | {}".format(
            item["timestamp"],
            item["user_id"],
            item["action"],
            item["details"]
        ))


def admin_portal(user):
    actions = {
        "1": ("Institution Overview", admin_overview),
        "2": ("View All Students", admin_all_students),
        "3": ("Search Records", admin_search),
        "4": ("Add Student + Login", admin_add_student),
        "5": ("Add Teacher + Login", admin_add_teacher),
        "6": ("Add Subject + Enrol Students", admin_add_subject),
        "7": ("Activate / Deactivate User", admin_manage_users),
        "8": ("Export Institutional Report", admin_export),
        "9": ("View Audit Logs", admin_audit_logs),
    }

    while True:
        heading("Administrator Portal")

        for key, (label, _) in actions.items():
            print("[{}] {}".format(key, label))

        print("[0] Logout")

        choice = ask("Select option: ")

        if choice == "0":
            return

        if choice in actions:
            actions[choice][1]()
        else:
            print("Invalid option.")

        pause()


# ======================== MAIN APPLICATION ========================

def main():
    ensure_files()

    print("\n")
    line()

    print("                  SEMESTER ZERO v2.0")
    print("       ROLE-BASED ACADEMIC ATTENDANCE INTELLIGENCE")

    line()

    print("Storage: interconnected CSV files")
    print("Authentication: PBKDF2 password hashing")

    if not MATPLOTLIB_AVAILABLE:
        print(
            "Matplotlib unavailable. Install with: "
            "py -m pip install matplotlib"
        )

    if not read_csv("users"):
        print("\nNo user accounts found.")
        print("Extract the sample CSV dataset into this folder.")
        return

    while True:
        user = authenticate()

        if not user:
            break

        role = user["role"].lower()

        try:
            if role == "student":
                student_portal(user)

            elif role == "teacher":
                teacher_portal(user)

            elif role == "admin":
                admin_portal(user)

            else:
                print("Unknown role. Contact the administrator.")

        except (KeyboardInterrupt, EOFError):
            print("\nAction cancelled; returning to login.")

        except Exception as error:
            print("\nAn error occurred: {}".format(error))
            print(
                "Check that all CSV files are present "
                "and have matching headers."
            )

        log_action(
            user["user_id"],
            "LOGOUT",
            "User logged out"
        )


if __name__ == "__main__":
    main()

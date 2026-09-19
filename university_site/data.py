from __future__ import annotations


FACULTIES = [
    {
        "name": "Faculty of Biological & Biomedical Sciences",
        "departments": ["Biology", "Medical Lab Technology", "Microbiology", "Public Health & Nutrition"],
    },
    {
        "name": "Faculty of Information Technology & Numerical Sciences",
        "departments": ["Information Technology", "Mathematics and Statistics", "Physics"],
    },
    {
        "name": "Faculty of Physical & Applied Sciences",
        "departments": [
            "Chemistry",
            "Earth Sciences",
            "Environmental Sciences",
            "Food Science and Technology",
            "Forestry & Wildlife Management",
            "Agricultural Sciences",
        ],
    },
    {
        "name": "Faculty of Social & Administrative Sciences",
        "departments": [
            "Economics",
            "Education",
            "History & Politics",
            "Islamic & Religious Studies",
            "Law",
            "Linguistics",
            "Psychology",
            "Sports Science & Physical Education",
            "Management Sciences",
        ],
    },
]

BS_PROGRAMS = {
    "Faculty of Biological & Biomedical Sciences": [
        "Botany", "Biochemistry", "Zoology", "Microbiology", "Medical Lab Technology",
        "Doctor of Physical Therapy (5 years)", "Anesthesia Technology", "Surgical Technology",
        "Virology & Immunology", "Radiology Technology", "Dental Technology",
        "Aesthetic and Cosmetology", "Public Health", "Human Nutrition and Dietetics",
        "Fisheries and Aquaculture",
    ],
    "Faculty of IT & Numerical Sciences": [
        "Computer Science", "Computer Science (Software Engineering)",
        "Computer Science (Artificial Intelligence)", "Computer Science (Data Science)",
        "Telecommunication & Networking", "Computer Science (Cyber Security)",
        "Computer Science (Robotics)", "Physics", "Mathematics", "Mathematics with AI", "Data Analytics",
    ],
    "Faculty of Physical and Applied Sciences": [
        "B.Sc (Hons) Agriculture", "Climate Change", "Chemistry", "Food Science & Technology",
        "Environmental Sciences", "Urban Forestry", "Geology", "Forestry & Wildlife Management",
    ],
    "Faculty of Social & Administrative Sciences": [
        "Bachelor of Education (Hons)", "Islamic & Religious Studies", "English (Language & Literature)",
        "Bachelor in Business Administration (BBA)", "Accounting & Finance",
        "Public Administration & Governance", "Business Analytics", "Tourism and Hospitality Management",
        "Pakistan Studies", "Political Science", "History", "International Relations", "Economics",
        "Psychology", "Sport Science & Physical Education",
    ],
}

MS_PROGRAMS = {
    "Faculty of Biological & Biomedical Sciences": [
        "Microbiology", "Human Nutrition and Dietetics", "Medical Lab Sciences", "Public Health",
        "Food & Dairy Microbiology", "Botany", "Zoology", "Biochemistry",
    ],
    "Faculty of IT & Numerical Sciences": ["Computer Science", "Software Engineering", "Mathematics", "Physics"],
    "Faculty of Physical and Applied Sciences": [
        "Agronomy", "Climate Change", "Horticulture", "Plant Breeding & Genetics", "Entomology",
        "Soil Science", "Food Sciences & Technology", "Environmental Science", "Wildlife Management",
        "Forestry", "Geology", "Chemistry",
    ],
    "Faculty of Social & Administrative Sciences": [
        "Accounting & Finance", "Education", "Economics", "Public Policy & Governance",
        "Islamic & Religious Studies", "Political Science", "Management Sciences",
        "Master in Business Administration (MBA 2 Years)",
    ],
}

PHD_PROGRAMS = {
    "Faculty of Biological & Biomedical Sciences": [
        "Medical Lab Sciences", "Microbiology", "Food & Dairy Microbiology", "Botany", "Zoology", "Biochemistry",
    ],
    "Faculty of IT & Numerical Sciences": ["Computer Science", "Mathematics"],
    "Faculty of Physical and Applied Sciences": [
        "Agronomy", "Horticulture", "Plant Breeding & Genetics", "Entomology", "Soil Science",
        "Food Sciences & Technology", "Environmental Science", "Wildlife Management", "Geology",
    ],
    "Faculty of Social & Administrative Sciences": [
        "Education", "Economics", "Public Policy and Governance", "Management Sciences",
        "Sports Science & Physical Education",
    ],
}

# The live admissions page floats two half-width blocks at a time in this
# visual order, placing Physical & Applied Sciences beside Biological Sciences.
PROGRAM_FACULTY_ORDER = (
    "Faculty of Biological & Biomedical Sciences",
    "Faculty of Physical and Applied Sciences",
    "Faculty of IT & Numerical Sciences",
    "Faculty of Social & Administrative Sciences",
)
BS_PROGRAMS = {name: BS_PROGRAMS[name] for name in PROGRAM_FACULTY_ORDER}
MS_PROGRAMS = {name: MS_PROGRAMS[name] for name in PROGRAM_FACULTY_ORDER}
PHD_PROGRAMS = {name: PHD_PROGRAMS[name] for name in PROGRAM_FACULTY_ORDER}

CONCESSION_PROGRAMS = {
    "Botany", "Biochemistry", "Zoology", "Virology & Immunology", "Public Health",
    "Human Nutrition and Dietetics", "Mathematics", "Mathematics with AI", "Data Analytics",
    "B.Sc (Hons) Agriculture", "Climate Change", "Chemistry", "Food Science & Technology",
    "Geology", "Forestry & Wildlife Management", "Bachelor of Education (Hons)",
    "Islamic & Religious Studies", "Public Administration & Governance", "Tourism and Hospitality Management",
}

SCHEDULE_ROWS = [
    ("Applications Open", "3rd August 2026"),
    ("Last Date of Online Application Submission", "1st September 2026"),
    ("Entry Test for MS/M.Phil/MBA & Ph.D Programs at UoH Campus", "6th September 2026"),
    ("Entry Test Result Announcement on UoH website", "8th September 2026"),
    ("Interviews of test-qualified candidates", "9th–10th September 2026"),
    ("Display of Merit List", "11th September 2026"),
    ("Fee Submission", "11th–16th September 2026"),
    ("Registration and Document Verification", "21st–25th September 2026"),
    ("Classes Begin", "28th September 2026"),
]

ELIGIBILITY_ROWS = [
    ("Management Sciences", "BBA / Accounting & Finance", "FA/FSc or equivalent with at least 45% marks."),
    ("Information Technology", "BS Computer Science and specializations", "Intermediate with Mathematics, ICS, or equivalent qualification with at least 50% marks."),
    ("Medical Lab Technology", "BS MLT / Allied Health Programs", "FSc Pre-Medical or equivalent with at least 50% marks."),
    ("Biology", "Botany / Zoology / Biochemistry", "FSc Pre-Medical or equivalent with at least 45% marks."),
    ("Public Health & Nutrition", "Public Health / Human Nutrition", "FSc Pre-Medical or equivalent with at least 45% marks."),
    ("Earth Sciences", "BS Geology", "FSc Pre-Medical, Pre-Engineering, ICS, or equivalent with at least 45% marks."),
    ("Education", "Bachelor of Education (Hons)", "FA/FSc or equivalent with at least 45% marks."),
    ("Linguistics", "BS English Language & Literature", "FA/FSc or equivalent with at least 45% marks."),
]

FEE_ROWS = [
    ("Social & Administrative Sciences", "BBA / Accounting & Finance", "52,230", "46,313"),
    ("Social & Administrative Sciences", "BS English", "48,330", "42,413"),
    ("IT & Numerical Sciences", "BS CS / SE / AI / Data Science / Cyber Security", "64,480", "58,563"),
    ("IT & Numerical Sciences", "BS Physics / Mathematics", "51,600", "45,683"),
    ("Biological & Biomedical Sciences", "Doctor of Physical Therapy", "78,795", "72,878"),
    ("Biological & Biomedical Sciences", "MLT / Surgical / Radiology / Anesthesia", "59,865", "53,948"),
    ("Physical & Applied Sciences", "Environmental Sciences", "51,600", "45,683"),
    ("Physical & Applied Sciences", "Food Science & Technology", "58,890", "52,973"),
    ("Law", "LLB", "74,920", "66,003"),
    ("Graduate Science", "MS/M.Phil", "77,060", "59,167"),
    ("Graduate Arts", "MS/M.Phil", "73,585", "55,692"),
    ("Doctoral Science", "Ph.D", "94,576", "69,362"),
]

SCHOLARSHIPS = [
    "Sibling fee reimbursement for real brothers and sisters",
    "Fee concession for students with disabilities",
    "Orphan fee concession",
    "HEC Merit and Need Based Scholarship",
    "Prime Minister Laptop Scheme",
    "Pakistan Bait-ul-Mal Scholarship",
    "Zakat Scholarship",
    "Sadaat Scholarship",
    "PPDA and other private scholarships",
]

FACILITIES = [
    "More than 50 bachelor, over 30 MS/M.Phil/M.Sc (Hons), and 24 PhD programs.",
    "Programs accredited by the relevant HEC councils.",
    "Transport routes serving Abbottabad, Havelian, Haripur, Wah, Hassanabdal, Taxila, Attock and Kamra.",
    "Girls hostel on campus and arranged boarding options subject to availability.",
    "Online access to results, attendance, and academic activities through student portals.",
    "Campus-wide internet, research and computing laboratories, and a digital library.",
    "IP-based security surveillance and a safe-university environment.",
    "National and international academic and industrial linkages.",
    "Sports, extracurricular activities, day-care, on-campus first aid and ambulance facility.",
    "Smoke- and drug-free campus.",
]

HOME_NEWS = [
    "Admissions open for Undergraduate & Graduate Programs (Admissions Fall 2026)",
    "UoH achieved another milestone in digitalization",
    "Circular regarding Professional Conduct & Conflict Resolution within UoH Premises",
    "HEC Policy on Protection against Sexual Harassment in HEIs 2021",
    "Higher Education Commission Policy on Drug & Tobacco Abuse in HEIs 2021",
]

RECENT_NEWS = [
    "The University of Haripur FP&AS Holds 1st Annual Review Meeting of Graduate Research Committees",
    "Tender Notice: UOH/ADV/114-2026",
    "Prof. Dr. Abid Farid Honoured as Chief Guest at NRTC Public Schools & Colleges Haripur",
    "The University of Haripur Senate Approves Record Rs. 2 Billion Budget",
    "Celebration of the Commencement of the PhD in Physics Program",
    "40th Meeting of the Syndicate Held at the University of Haripur",
]

STUDENT_DATA = {
    "name": "Demo Student",
    "registration": "UOH-DEMO-2026-001",
    "program": "BS Software Engineering",
    "semester": "8",
    "status": "Active",
    "courses": [
        ("SE-421", "Software Project Management", "3", "Dr. Demo Faculty"),
        ("CS-417", "Information Security", "3", "Ms. Demo Instructor"),
        ("CS-409", "Artificial Intelligence", "3", "Dr. Sample Lecturer"),
        ("SE-499", "Final Year Project", "6", "Demo Supervisor"),
        ("SE-423", "Software Quality Engineering", "3", "Mr. Sample Faculty"),
    ],
    "attendance": [
        ("Software Project Management", "88%"),
        ("Information Security", "91%"),
        ("Artificial Intelligence", "84%"),
        ("Final Year Project", "95%"),
        ("Software Quality Engineering", "87%"),
    ],
    "results": [
        ("Artificial Intelligence", "A", "4.00"),
        ("Information Security", "A-", "3.67"),
        ("Software Quality Engineering", "B+", "3.33"),
        ("Software Project Management", "A-", "3.67"),
    ],
    "fees": [("Spring 2026 Semester Fee", "58,563", "Paid"), ("Examination Fee", "3,500", "Paid")],
    "timetable": [
        ("Monday", "09:00–10:30", "Information Security", "CS Lab 2"),
        ("Tuesday", "11:00–12:30", "Artificial Intelligence", "Room 204"),
        ("Wednesday", "09:00–10:30", "Software Project Management", "Room 112"),
        ("Thursday", "13:00–16:00", "Final Year Project", "FYP Lab"),
    ],
    "notices": [
        ("12 Aug 2026", "FYP progress presentation schedule published."),
        ("08 Aug 2026", "Semester examination form submission is open."),
        ("01 Aug 2026", "Library clearance is required before final transcript processing."),
    ],
}


PUBLIC_INFORMATION_PAGES = {
    "faculty-profile": ("Faculty Profile", ["Browse academic departments and the synthetic faculty roles represented by the local university structure.", "Department pages identify their faculty, programs, academic office, and locally assigned demo employees."], ["Academic departments", "Programs and teaching areas", "Faculty office information"]),
    "alumni": ("Alumni Information", ["This local public page describes demonstration alumni engagement, graduate networking, and career-support activities.", "No real alumni accounts or personal records are stored in this environment."], ["Graduate networking", "Career development events", "Synthetic alumni outreach calendar"]),
    "ptis": ("Public Teaching Information", ["Public teaching information summarizes the academic structure without exposing employee-only assignments or student records."], ["Department directory", "Program structure", "Academic calendar information"]),
    "downloads": ("Public Downloads", ["Publicly classified local documents and admissions instructions are available through their relevant pages."], ["Admissions instructions", "Public academic policies", "Program and eligibility information"]),
    "online-results": ("Online Results Information", ["Individual results are available only after local Student Portal authentication.", "The public page does not expose student grades or registration records."], ["Student Portal result access", "Transcript-preview guidance", "Examination contact workflow"]),
    "jobs-careers": ("Jobs and Careers", ["Synthetic vacancy and career-service information is used for the local demonstration.", "No production applications are accepted by this site."], ["Career-development workshops", "Synthetic vacancy notices", "Application safety guidance"]),
    "tenders": ("Public Tender Notices", ["This demonstration lists only synthetic procurement notices and does not accept quotations or vendor records."], ["DEMO-TENDER-2026-01 — Laboratory consumables", "DEMO-TENDER-2026-02 — Campus maintenance services", "DEMO-TENDER-2026-03 — Library shelving"]),
    "central-library": ("Central Library", ["The library supports learning and research through print, digital, and reference services represented in this local information environment."], ["Membership and borrowing", "Digital-resource guidance", "Library public policies"]),
    "semester-rules": ("Semester Rules", ["Public academic rules cover registration, attendance, assessment, grading, and academic standing.", "Student-specific status remains inside the authenticated Student Portal."], ["Registration timelines", "Attendance requirements", "Assessment and grading", "Academic probation"]),
    "statutes": ("University Statutes Information", ["This public demonstration provides an overview of governance and approved public policy structures.", "Controlled governance records remain role-restricted in the Employee Portal."], ["Governance framework", "Authority delegation", "Public record-retention principles"]),
    "vice-chancellor-office": ("Vice Chancellor's Office", ["The office provides strategic leadership, institutional oversight, and executive approval within the synthetic university hierarchy."], ["Strategic governance", "Institutional planning", "Executive compliance"]),
    "registrar-office": ("Registrar Office", ["The Registrar Office coordinates academic administration, official correspondence, records, notifications, and statutory meeting support."], ["Academic records administration", "Official notifications", "Document authentication", "Statutory meeting coordination"]),
    "qec": ("Quality Enhancement Cell", ["The Quality Enhancement Cell supports program review, teaching-quality processes, and continuous institutional improvement."], ["Self-assessment coordination", "Program review", "Quality indicators", "Academic feedback"]),
    "examinations": ("Examinations Section", ["The Examinations Section coordinates schedules, duty assignments, result processing, and transcript workflows under controlled policies."], ["Examination schedules", "Invigilation coordination", "Result administration", "Transcript workflow"]),
    "it-services": ("Directorate of IT Services", ["The Directorate of IT Services supports accounts, networks, systems, service requests, security controls, and local academic platforms."], ["Account support", "Network services", "System administration", "Information-security guidance"]),
    "journal-management": ("Journal of Management", ["This local page describes a synthetic academic journal context for management and administrative research."], ["Research themes", "Editorial workflow", "Publication ethics"]),
    "journal-religious-studies": ("Journal of Islamic and Religious Studies", ["This local page presents public journal-scope and publication-ethics information without reproducing external articles."], ["Religious-studies research", "Editorial review", "Publication integrity"]),
    "journal-education": ("Haripur Journal of Educational Research", ["This local page presents a synthetic educational-research journal profile and author-guidance context."], ["Teaching and learning research", "Educational policy", "Research ethics"]),
    "oric": ("Office of Research, Innovation and Commercialization", ["ORIC coordinates synthetic research-support, ethics, intellectual-property, and collaboration workflows."], ["Research support", "Innovation services", "Intellectual property", "Industry collaboration"]),
    "bic": ("Business Incubation Center", ["The Business Incubation Center supports demonstration entrepreneurship, mentoring, and enterprise-development activities."], ["Startup mentoring", "Business development", "Innovation events"]),
    "asrb": ("Advanced Studies and Research Board", ["ASRB information summarizes graduate-research oversight, proposal review, and academic-quality responsibilities."], ["Graduate research review", "Supervisor and proposal oversight", "Research-quality governance"]),
    "fact-sheet": ("University Fact Sheet", ["The local dataset represents four faculties, twenty-two departments, twenty-two undergraduate programs, two hundred students, and thirty employees."], ["4 faculties", "22 departments", "22 programs", "200 synthetic students", "30 synthetic employees"]),
    "annual-report": ("Annual Report Overview", ["This demonstration annual-report page summarizes academic, governance, and service activity using synthetic local information only."], ["Academic activity", "Student services", "Research and quality", "Institutional operations"]),
    "anti-harassment": ("Protection and Respect", ["The university environment requires respectful conduct, accessible reporting, confidentiality, and protection against retaliation."], ["Respectful workplace and study", "Confidential reporting", "Non-retaliation", "Support and referral"]),
    "planning-development": ("Planning and Development", ["Planning and Development coordinates synthetic institutional plans, project monitoring, and service-improvement records."], ["Strategic planning", "Project monitoring", "Infrastructure planning"]),
    "career-development": ("Career Development Center", ["The Career Development Center supports students through synthetic workshops, employer-engagement exercises, and career-readiness resources."], ["Career counseling", "Skills workshops", "Employer engagement"]),
    "central-research-lab": ("Central Research Laboratory", ["The Central Research Laboratory provides a controlled demonstration of shared research facilities, safety expectations, and booking workflows."], ["Shared equipment", "Laboratory safety", "Research support"]),
}

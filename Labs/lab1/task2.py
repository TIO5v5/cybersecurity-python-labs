# Вхідні дані Варіант 11
users = {
    "risk_manager": {
        "role": "risk_analyst",
        "clearance": 4,
        "department": "Risk Management",
        "active": True,
    },
    "business_analyst": {
        "role": "business_analyst",
        "clearance": 2,
        "department": "Business",
        "active": True,
    },
    "legal_counsel": {
        "role": "legal",
        "clearance": 3,
        "department": "Legal",
        "active": True,
    },
    "contractor_dev": {
        "role": "contractor",
        "clearance": 2,
        "department": "Contract",
        "active": True,
    },
    "obsolete_system": {
        "role": "legacy_system",
        "clearance": 1,
        "department": "Legacy",
        "active": False,
    },
}

resources = [
    ("risk_registers", 4),
    ("business_requirements", 2),
    ("legal_documents", 3),
    ("contract_code", 2),
    ("governance_framework", 4),
    ("meeting_minutes", 1),
    ("regulatory_reports", 3),
    ("executive_dashboards", 4),
    ("project_specs", 2),
    ("public_statements", 1),
]

security_levels = ("Public", "Internal Use", "Restricted", "Highly Restricted")
blocked_users = {"obsolete_system", "contract_expired", "legal_hold"}


def main():
    # 2. Виведення списку ресурсів із текстовими назвами рівнів безпеки
    print(f"{'Ресурс':<25} | {'Рівень безпеки'}")
    print("-" * 50)
    for res_name, res_level in resources:
        # res_level йде від 1 до 4, а індекси кортежу від 0 до 3
        level_name = security_levels[res_level - 1]
        print(f"{res_name:<25} | {level_name}")

    print("\n" + "=" * 60 + "\n")

    # 3. Перевірка доступу (беремо користувачів з бази, заблокованих та одного невідомого для тесту)
    users_to_test = list(users.keys()) + list(blocked_users) + ["unknown_hacker"]
    # Прибираємо дублікати, щоб не перевіряти двічі
    users_to_test = list(dict.fromkeys(users_to_test))

    for user in users_to_test:
        for res_name, res_level in resources:
            if user not in users:
                status = "DENY (User not found)"
            elif user in blocked_users:
                status = "DENY (User is blocked)"
            elif not users[user]["active"]:
                status = "DENY (Account inactive)"
            elif users[user]["clearance"] >= res_level:
                status = "ALLOW"
            else:
                status = "DENY (Insufficient clearance)"

            # 4. Виведення результату
            print(f"user={user} resource={res_name} -> {status}")


if __name__ == "__main__":
    main()

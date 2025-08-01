def split_bill():
    num_people = int(input("Enter number of people: "))
    expenses = {}
    for _ in range(num_people):
        name = input("Enter person's name: ")
        amount = float(input(f"Enter amount spent by {name}: "))
        expenses[name] = amount
    total_amount = sum(expenses.values())
    fair_share = total_amount / num_people

    print(f"\nTotal amount: ₹{total_amount:.2f}")
    print(f"Each person's share: ₹{fair_share:.2f}\n")

    balances = {person: paid - fair_share for person, paid in expenses.items()}
    creditors = {p: amt for p, amt in balances.items() if amt > 0}
    debtors = {p: -amt for p, amt in balances.items() if amt < 0}
    settlements = []

    for debtor, debt_amt in debtors.items():
        for creditor in list(creditors):
            if debt_amt == 0:
                break
            credit_amt = creditors[creditor]
            pay_amt = min(debt_amt, credit_amt)
            settlements.append(f"{debtor} pays ₹{pay_amt:.2f} to {creditor}")
            debt_amt -= pay_amt
            creditors[creditor] -= pay_amt
            if creditors[creditor] == 0:
                del creditors[creditor]
    if settlements:
        print("Who pays whom how much:")
        for s in settlements:
            print(s)
    else:
        print("All expenses are already settled.")


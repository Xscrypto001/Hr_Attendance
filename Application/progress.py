from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from datetime import date
from .models import LeaveApplication

@login_required
def leave_balances(request):
    leave_types = [
        ("Vacaton", "#ec4899"),
        ("Maternity ", "#22c55e"),
        ("Unpaid", "#facc15"),
        ("Educational", "#3b82f6")
    ]

    leave_data = []
    circumference = 283  # circle circumference for SVG

    for leave_type, color in leave_types:
        leaves = LeaveApplication.objects.filter(
            applicant=request.user,
            leave_type__icontains=leave_type,
            final_status="approved"
        )

        total_days_taken = sum([leave.total_days() for leave in leaves])

        max_days = {
            "Vacaton": 10,
            "Educational": 15,
            "Unpaid": 15,
            "Educational": 27
        }.get(leave_type, 0)

        balance = max_days - total_days_taken
        if balance < 0:
            balance = 0

        # Compute stroke offset here
        if max_days > 0:
            stroke_offset = circumference - (circumference * (balance / max_days))
        else:
            stroke_offset = circumference

        leave_data.append({
            "name": f"{leave_type} Leave" if leave_type != "Floater" else "Floater Holiday",
            "balance": balance,
            "color": color,
            "max_days": max_days,
            "stroke_offset": stroke_offset
        })

    return render(request, "Application/progress.html", {"leave_data": leave_data})

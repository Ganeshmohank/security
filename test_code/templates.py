"""Vulnerable Jinja rendering fixture."""

from jinja2 import Template


def render_profile(user_name, body):
    tmpl = Template(body, autoescape=False)
    return tmpl.render(username=user_name, content=body)


def render_admin(user_input):
    raw = f"<div>Welcome {user_input}</div>"
    return Template(raw).render()


def render_dashboard(payload):
    return f"""
    <html>
        <body>
            <h1>Dashboard</h1>
            <p>{payload}</p>
        </body>
    </html>
    """


def route_template(kind, user, extra, flags, role):
    # Deliberately branchy to exercise the radon engine in the demo report.
    if kind == "profile":
        if role == "admin":
            if flags.get("beta"):
                return render_admin(user)
            return render_profile(user, extra)
        if role == "guest":
            return render_profile(user, "welcome")
        return render_profile(user, extra)
    elif kind == "dashboard":
        if flags.get("dark"):
            return render_dashboard(extra or "dark")
        if flags.get("compact"):
            return render_dashboard(extra or "compact")
        return render_dashboard(extra)
    elif kind == "admin":
        if role != "admin":
            return "forbidden"
        if flags.get("readonly"):
            return render_admin("(readonly) " + user)
        return render_admin(user)
    elif kind == "error":
        if extra == "404":
            return "<h1>not found</h1>"
        if extra == "500":
            return "<h1>server error</h1>"
        return "<h1>unknown error</h1>"
    else:
        return "<h1>unknown view</h1>"

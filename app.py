from flask import Flask, render_template

from sniffer import logs, start_sniffer

import threading

app = Flask(__name__)

# ============================================

# DASHBOARD ROUTE

# ============================================

@app.route("/")

def index():

    return render_template(

        "index.html",

        logs=logs[::-1]

    )

# ============================================

# START SNIFFER IN BACKGROUND

# ============================================

def run_sniffer():

    start_sniffer()

# ============================================

# MAIN APP

# ============================================

if __name__ == "__main__":

    sniffer_thread = threading.Thread(

        target=run_sniffer

    )

    sniffer_thread.daemon = True

    sniffer_thread.start()

    app.run(

        host="0.0.0.0",

        port=5000,

        debug=True

    )

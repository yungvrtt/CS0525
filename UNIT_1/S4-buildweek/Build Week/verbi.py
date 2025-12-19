import http.client

def test_metodi(host, port, path):
    methods = ["OPTIONS", "GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"]
    results = {}
    conn = None

    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)

        for method in methods:
            conn.request(method, path)
            response = conn.getresponse()
            response.read()  # svuota il body
            results[method] = (response.status, response.reason)

    except ConnectionRefusedError:
        print("Connessione rifiutata dal server")

    except Exception as e:
        print("Errore:", e)

    finally:
        if conn:
            conn.close()

    return results



host = input("Inserire host/IP del sistema target: ")
port = input("Inserire la porta del sistema target (default 80): ")
path = input("inserisci il root: ")

port = 80 if port == "" else int(port)
path = "/" if path == "" else str(path)

results = test_metodi(host, port, path)

print("\nRisultati verifica verbi HTTP:")
for method, (status, reason) in results.items():
    print(f"{method}: {status} {reason}")
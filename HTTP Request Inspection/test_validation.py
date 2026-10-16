from response_handler import ResponseHandler

handler = ResponseHandler()

try:
    handler.handle("INVALID", "127.0.0.1", "Validation test")
    print("UNEXPECTED: Invalid action was accepted")
except ValueError as error:
    print("PASS: Invalid action rejected")
    print(f"DETAIL: {error}")

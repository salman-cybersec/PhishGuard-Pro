
class RequestSizeLimitMiddleware:
    def __init__(self, app, max_size: int):
        self.app = app
        self.max_size = max_size

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = None

        for name, value in scope.get("headers", []):
            if name.lower() == b"content-length":
                try:
                    content_length = int(value)
                except ValueError:
                    await self._reject(send, 400, "Invalid Content-Length.")
                    return

                break

        if content_length is not None:
            if content_length < 0:
                await self._reject(send, 400, "Invalid Content-Length.")
                return

            if content_length > self.max_size:
                await self._reject(send, 413, "Request body is too large.")
                return

        messages = []
        total_size = 0

        while True:
            message = await receive()

            if message["type"] == "http.disconnect":
                return

            if message["type"] != "http.request":
                continue

            body = message.get("body", b"")
            total_size += len(body)

            if total_size > self.max_size:
                await self._reject(send, 413, "Request body is too large.")
                return

            messages.append(message)

            if not message.get("more_body", False):
                break

        message_index = 0

        async def receive_replay():
            nonlocal message_index

            if message_index < len(messages):
                message = messages[message_index]
                message_index += 1
                return message

            return {
                "type": "http.request",
                "body": b"",
                "more_body": False,
            }

        await self.app(scope, receive_replay, send)

    async def _reject(self, send, status_code: int, detail: str):
        body = (
            '{"detail":"' + detail + '"}'
        ).encode("utf-8")

        await send({
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"cache-control", b"no-store"),
            ],
        })

        await send({
            "type": "http.response.body",
            "body": body,
        })

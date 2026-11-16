from phishguard.website_preview import create_safe_preview


def test_preview_preserves_safe_page_content():
    html = """
    <html>
      <body>
        <header>My Website</header>
        <main>
          <h1>Welcome</h1>
          <p>This is an authorized test page.</p>
        </main>
        <footer>Contact us</footer>
      </body>
    </html>
    """

    result = create_safe_preview(html)

    assert "<header>My Website</header>" in result
    assert "<h1>Welcome</h1>" in result
    assert "This is an authorized test page." in result
    assert "<footer>Contact us</footer>" in result


def test_preview_does_not_execute_imported_javascript():
    html = """
    <h1>Test Page</h1>
    <script>
        document.body.innerHTML = "Changed";
    </script>
    """

    result = create_safe_preview(html)

    assert "<script" not in result.lower()
    assert "document.body.innerHTML" not in result
    assert "<h1>Test Page</h1>" in result


def test_preview_removes_embedded_forms():
    html = """
    <h1>Sample Page</h1>
    <form>
        <input name="username">
        <input type="password">
        <button>Submit</button>
    </form>
    """

    result = create_safe_preview(html)

    assert "<form" not in result.lower()
    assert "<input" not in result.lower()
    assert "password" not in result.lower()
    assert "AUTHORIZED SECURITY AWARENESS SIMULATION" in result

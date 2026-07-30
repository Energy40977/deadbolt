package net.acme.billing.webview

class StatementView(private val webView: WebView) {
    fun attach() {
        // deadbolt-expect DB-MOB-003:high
        webView.addJavascriptInterface(StatementBridge(), "native")
    }
}

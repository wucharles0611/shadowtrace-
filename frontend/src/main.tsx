import React from "react";
import ReactDOM from "react-dom/client";

function App() {
  return (
    <main
      style={{
        minHeight: "100vh",
        display: "grid",
        placeItems: "center",
        fontFamily: "Georgia, 'Times New Roman', serif",
        background: "linear-gradient(160deg, #0b1c2c 0%, #16324f 55%, #1f4b6e 100%)",
        color: "#e8eef4",
        margin: 0,
      }}
    >
      <h1 style={{ fontSize: "3rem", letterSpacing: "0.04em", fontWeight: 500 }}>ShadowTrace</h1>
    </main>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);

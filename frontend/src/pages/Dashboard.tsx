function RedeemForm({ api, onSuccess }: any) {
  const [code, setCode] = useState("");

  async function redeem() {
    const token = localStorage.getItem("fb_autoshare_token");
    if (!token) return alert("Login first");
    try {
      const res = await axios.post(`${api}/api/auth/redeem`, { code, token });
      onSuccess(res.data);
      alert("Redeemed successfully");
    } catch (err: any) {
      alert(err.response?.data?.error ?? "Redeem failed");
    }
  }

  return (
    <div>
      <input
        className="w-full border p-2 rounded mb-2"
        placeholder="CODE"
        value={code}
        onChange={(e) => setCode(e.target.value)}
      />
      <button onClick={redeem} className="px-3 py-2 bg-yellow-600 text-white rounded">Redeem</button>
    </div>
  );
}
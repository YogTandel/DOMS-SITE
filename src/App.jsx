import MainPage from "./Components/MainPage";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Login from "./Pages/Auth/Login";
import Logout from "./Pages/Auth/Logout";
import Register from "./Pages/Auth/Register";
import Forgotpassword from "./Pages/Auth/Forgotpassword";
import Confirmmail from "./Pages/Auth/Confirmmail";
import Resetpassword from "./Pages/Auth/Resetpassword";
import Lockscreen from "./Pages/Auth/Lockscreen";

function App() {
  return (
    <Router basename="/">
      <Routes>
        <Route path="/dashboard" element={<MainPage />} />
        <Route path="/" element={<Login />} />
        <Route path="/logout" element={<Logout />} />
        <Route path="/register" element={<Register />} />
        <Route path="/forgotpassword" element={<Forgotpassword />} />
        <Route path="/confirmmail" element={<Confirmmail />} />
        <Route path="/resetpassword" element={<Resetpassword />} />
        <Route path="/lockscreen" element={<Lockscreen />} />
      </Routes>
    </Router>
  );
}

export default App;

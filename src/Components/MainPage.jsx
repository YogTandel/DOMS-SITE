import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import "./customepagination.css";
import axios from "axios";

function MainPage() {
  const [isAdmin, setIsAdmin] = useState(false);
  // eslint-disable-next-line no-unused-vars
  const [activeView, setActiveView] = useState("dashboard");
  const [users, setUsers] = useState([]); // Dynamic user data
  const [currentPage, setCurrentPage] = useState(1);
  const [showModal, setShowModal] = useState(false);
  const [newAdmin, setNewAdmin] = useState({
    email: "",
    password: "",
    date: "",
    role: "",
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showPageModal, setShowPageModal] = useState(false); // For controlling modal visibility
  const [selectedPages, setSelectedPages] = useState([]); // Stores selected pages
  const [currentUser, setCurrentUser] = useState(null); // Stores the current user being edited
  const role = localStorage.getItem("role");
  const navigate = useNavigate();

  const handlePasswordToggle = () => {
    setShowPassword(!showPassword);
  };

  const validatePassword = (password) => {
    const lengthValid = password.length >= 6;
    const lowerCaseValid = /[a-z]/.test(password);
    const upperCaseValid = /[A-Z]/.test(password);
    const digitValid = /\d/.test(password);

    return { lengthValid, lowerCaseValid, upperCaseValid, digitValid };
  };

  const passwordValidation = validatePassword(newAdmin.password);

  const pageSize = 5;
  const totalPages = Math.ceil(users.length / pageSize);

  const handlePageChange = (pageNumber) => {
    setCurrentPage(pageNumber);
  };

  const handleLogout = async () => {
    const role = localStorage.getItem("role"); // Get user role
    let signoutEndpoint = "";

    if (role === "admin") {
      signoutEndpoint = "https://doms-backend.vercel.app/api/admin/signout";
    } else if (role === "superadmin") {
      signoutEndpoint = "https://doms-backend.vercel.app/api/superadmin/signout";
    }

    if (signoutEndpoint) {
      try {
        const response = await fetch(signoutEndpoint, {
          method: "POST",
          credentials: "include",
        });

        const data = await response.json();

        if (data.success) {
          console.log("✅ Logout successful");
          localStorage.removeItem("role"); // Clear role
          navigate("/"); // Redirect to login
        } else {
          console.error("❌ Logout failed:", data.message);
        }
      } catch (error) {
        console.error("❌ Error during logout:", error);
      }
    }
  };

  const togglePageModal = (user) => {
    setCurrentUser(user); // Set the current user
    setSelectedPages(user.permission ? user.permission.split(", ") : []); // Load selected pages for that user
    setShowPageModal(!showPageModal); // Open/close modal
  };

  // Toggle selection of a page for the current user
  const togglePage = (page) => {
    setSelectedPages(
      (prevPages) =>
        prevPages.includes(page)
          ? prevPages.filter((p) => p !== page) // Deselect page
          : [...prevPages, page] // Select page
    );
  };

  // Save selected pages to the current user
  const handleSavePage = () => {
    const updatedUsers = users.map((u) =>
      u.email === currentUser.email
        ? {
            ...u,
            permission: selectedPages.join(", "), // Save pages as comma-separated string
          }
        : u
    );
    setUsers(updatedUsers);
    localStorage.setItem("users", JSON.stringify(updatedUsers));
    setShowPageModal(false); // Close modal after saving
  };

  // ✅ Token Verification (If JWT is Used)
  const checkToken = useCallback(() => {
    const token = localStorage.getItem("token"); // Get stored token

    if (!token) {
      console.warn("❌ No token found, redirecting...");
      navigate("/");
      return;
    }

    axios
      .get("https://doms-backend.vercel.app/api/auth/verifyToken", {
        headers: { Authorization: `Bearer ${token}` }, // ✅ If using JWT authentication
        withCredentials: true, // Only needed if cookies are used too
      })
      .then((response) => {
        if (response.data.success) {
          console.log("✅ Session verified, user is authenticated");
        } else {
          console.warn("❌ No active session, redirecting to login...");
          navigate("/");
        }
      })
      .catch((error) => {
        console.error("❌ Session verification failed:", error);
        navigate("/");
      });
  }, [navigate]); // ✅ `navigate` is a stable dependency

  // ✅ Fetch Users (Only if session is valid)
  const fetchUsers = useCallback(async () => {
    const role = localStorage.getItem("role")?.toLowerCase(); // 🔥 Convert role to lowercase

    if (!role) {
      console.warn("❌ Unauthorized: No role found in localStorage.");
      return;
    }

    try {
      const response = await fetch("https://doms-backend.vercel.app/api/admin/admins", {
        method: "GET",
        credentials: "include", // ✅ Required for session-based authentication
      });

      const result = await response.json();
      console.log("✅ Fetched Admin Data:", result);

      if (result.success && Array.isArray(result.data)) {
        setUsers(result.data);
      } else {
        console.error("❌ Unexpected data format: ", result);
      }
    } catch (error) {
      console.error("❌ Error fetching users:", error);
    }
  }, []);

  // ✅ Initial Session Check & Fetch Users
  useEffect(() => {
    axios
      .get("https://doms-backend.vercel.app/session", { withCredentials: true })
      .then((response) => {
        if (response.data.success) {
          console.log("✅ Session Data:", response.data.session);

          const userRole = response.data.session.role; // Get role from session
          localStorage.setItem("role", userRole); // Store in localStorage

          if (userRole === "admin" || userRole === "superadmin") {
            console.log("✅ Role allowed, fetching users...");
            fetchUsers();
          } else {
            console.warn("❌ Unauthorized role:", userRole);
          }
        } else {
          console.warn("❌ No session found, checking token...");
          checkToken(); // Check token if session is missing
        }
      })
      .catch((error) => {
        console.error("❌ Session check failed:", error);
        checkToken(); // Try token authentication if session check fails
      });
  }, [fetchUsers, checkToken]);

  // Slice the users array to get only the users for the current page
  const currentUsers = users.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize
  );

  const handlePrev = () => {
    if (currentPage > 1) {
      setCurrentPage(currentPage - 1);
    }
  };

  const handleNext = () => {
    if (currentPage < totalPages) {
      setCurrentPage(currentPage + 1);
    }
  };

  const handleCreateAdmin = () => {
    setShowModal(true);
  };

  const handleSaveAdmin = async () => {
    if (!newAdmin.email || !newAdmin.password.trim() || !newAdmin.role) {
      alert("❌ Please fill in all fields, including password!");
      return;
    }

    try {
      const formattedDate =
        newAdmin.date || new Date().toISOString().split("T")[0];

      // Store password before resetting state
      const tempPassword = newAdmin.password;

      const response = await fetch("https://doms-backend.vercel.app/api/admin/signup", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: newAdmin.email,
          password: tempPassword,
          date: formattedDate,
          role: newAdmin.role,
        }),
      });

      // Log the response status and data to check what is being returned
      const data = await response.json();
      console.log("API Response:", data);

      if (response.ok) {
        alert(
          `✅ Admin created successfully!\nEmail: ${data.result.email}\nPassword: ${tempPassword}`
        );

        // Now copy credentials to clipboard before resetting state
        copyCredentials(data.result.email, tempPassword, data.result.role);

        setShowModal(false);
        setNewAdmin({ email: "", password: "", date: "", role: "" });
        fetchUsers();
      } else {
        alert(`❌ Error: ${data.message || response.statusText}`);
      }
    } catch (error) {
      console.error("Error saving admin:", error);
      alert("❌ An unexpected error occurred. Please try again.");
    }
  };

  const handleAdminActionChange = () => {
    setActiveView("admin");
    setIsAdmin(true);
  };

  const handleDashboardActionChange = () => {
    setActiveView("dashboard");
    setIsAdmin(false);
  };

  const copyCredentials = (email, password, role) => {
    if (!password) {
      alert("⚠️ Password is missing! Try creating the admin again.");
      return;
    }

    const credentials = `Email: ${email}\nPassword: ${password}\nRole: ${role}`;
    navigator.clipboard
      .writeText(credentials)
      .then(() => {
        alert("📋 Credentials copied to clipboard!");
      })
      .catch((err) => {
        console.error("Failed to copy credentials: ", err);
        alert("❌ Failed to copy credentials. Please try again.");
      });
  };

  return (
    <div className="main" id="top">
      <div className="container-fluid" data-layout="container">
        <nav className="navbar navbar-light navbar-vertical navbar-expand-xl">
          <div className="d-flex align-items-center">
            <div className="toggle-icon-wrapper">
              <button
                className="btn navbar-toggler-humburger-icon navbar-vertical-toggle"
                data-bs-toggle="tooltip"
                data-bs-placement="left"
                title="Toggle Navigation"
              >
                <span className="navbar-toggle-icon">
                  <span className="toggle-line" />
                </span>
              </button>
            </div>
            <Link className="navbar-brand" to="/dashboard">
              <div className="d-flex align-items-center py-3">
                <span className="font-sans-serif">Dashboard</span>
              </div>
            </Link>
          </div>
          <div className="collapse navbar-collapse" id="navbarVerticalCollapse">
            <div className="navbar-vertical-content scrollbar">
              <ul
                className="navbar-nav flex-column mb-3"
                id="navbarVerticalNav"
              >
                <li className="nav-item">
                  <a
                    className="nav-link"
                    href="#dashboard"
                    onClick={handleDashboardActionChange}
                    role="button"
                    data-bs-toggle="collapse"
                    aria-expanded="true"
                    aria-controls="dashboard"
                  >
                    <div className="d-flex align-items-center">
                      <span className="nav-link-icon">
                        <span className="fas fa-chart-pie" />
                      </span>
                      <span className="nav-link-text ps-1">Dashboard</span>
                    </div>
                  </a>
                  <a
                    className="nav-link"
                    href="#admin"
                    role="button"
                    onClick={handleAdminActionChange}
                    data-bs-toggle="collapse"
                    aria-expanded="true"
                    aria-controls="admin"
                  >
                    <span className="nav-link-text ps-1">Admin</span>
                  </a>
                </li>
                <li className="nav-item">
                  {/* label*/}
                  <div className="row navbar-vertical-label-wrapper mt-3 mb-2">
                    <div className="col-auto navbar-vertical-label">App</div>
                    <div className="col ps-0">
                      <hr className="mb-0 navbar-vertical-divider" />
                    </div>
                  </div>
                  {/* parent pages*/}
                  <a
                    className="nav-link dropdown-indicator"
                    href="#e-commerce"
                    role="button"
                    data-bs-toggle="collapse"
                    aria-expanded="false"
                    aria-controls="e-commerce"
                  >
                    <div className="d-flex align-items-center">
                      <span className="nav-link-icon">
                        <span className="fas fa-shopping-cart" />
                      </span>
                      <span className="nav-link-text ps-1">Orders</span>
                    </div>
                  </a>
                  <ul className="nav collapse false" id="e-commerce">
                    <li className="nav-item">
                      <a
                        className="nav-link dropdown-indicator"
                        href="#product"
                        data-bs-toggle="collapse"
                        aria-expanded="false"
                        aria-controls="e-commerce"
                      >
                        <div className="d-flex align-items-center">
                          <span className="nav-link-text ps-1">Product</span>
                        </div>
                      </a>
                      {/* more inner pages*/}
                      <ul className="nav collapse false" id="product">
                        <li className="nav-item">
                          <a
                            className="nav-link"
                            href="app/e-commerce/product/product-list.html"
                            aria-expanded="false"
                          >
                            <div className="d-flex align-items-center">
                              <span className="nav-link-text ps-1">
                                Product list
                              </span>
                            </div>
                          </a>
                          {/* more inner pages*/}
                        </li>
                        <li className="nav-item">
                          <a
                            className="nav-link"
                            href="app/e-commerce/product/product-grid.html"
                            aria-expanded="false"
                          >
                            <div className="d-flex align-items-center">
                              <span className="nav-link-text ps-1">
                                Product grid
                              </span>
                            </div>
                          </a>
                          {/* more inner pages*/}
                        </li>
                        <li className="nav-item">
                          <a
                            className="nav-link"
                            href="app/e-commerce/product/product-details.html"
                            aria-expanded="false"
                          >
                            <div className="d-flex align-items-center">
                              <span className="nav-link-text ps-1">
                                Product details
                              </span>
                            </div>
                          </a>
                          {/* more inner pages*/}
                        </li>
                      </ul>
                    </li>
                    <li className="nav-item">
                      <a
                        className="nav-link dropdown-indicator"
                        href="#orders"
                        data-bs-toggle="collapse"
                        aria-expanded="false"
                        aria-controls="e-commerce"
                      >
                        <div className="d-flex align-items-center">
                          <span className="nav-link-text ps-1">Orders</span>
                        </div>
                      </a>
                      {/* more inner pages*/}
                      <ul className="nav collapse false" id="orders">
                        <li className="nav-item">
                          <a
                            className="nav-link"
                            href="app/e-commerce/orders/order-list.html"
                            aria-expanded="false"
                          >
                            <div className="d-flex align-items-center">
                              <span className="nav-link-text ps-1">
                                Order list
                              </span>
                            </div>
                          </a>
                          {/* more inner pages*/}
                        </li>
                        <li className="nav-item">
                          <a
                            className="nav-link"
                            href="app/e-commerce/orders/order-details.html"
                            aria-expanded="false"
                          >
                            <div className="d-flex align-items-center">
                              <span className="nav-link-text ps-1">
                                Order details
                              </span>
                            </div>
                          </a>
                          {/* more inner pages*/}
                        </li>
                      </ul>
                    </li>
                    <li className="nav-item">
                      <a
                        className="nav-link"
                        href="app/e-commerce/customers.html"
                        aria-expanded="false"
                      >
                        <div className="d-flex align-items-center">
                          <span className="nav-link-text ps-1">Customers</span>
                        </div>
                      </a>
                      {/* more inner pages*/}
                    </li>
                    <li className="nav-item">
                      <a
                        className="nav-link"
                        href="app/e-commerce/customer-details.html"
                        aria-expanded="false"
                      >
                        <div className="d-flex align-items-center">
                          <span className="nav-link-text ps-1">
                            Customer details
                          </span>
                        </div>
                      </a>
                      {/* more inner pages*/}
                    </li>
                    <li className="nav-item">
                      <a
                        className="nav-link"
                        href="app/e-commerce/shopping-cart.html"
                        aria-expanded="false"
                      >
                        <div className="d-flex align-items-center">
                          <span className="nav-link-text ps-1">
                            Shopping cart
                          </span>
                        </div>
                      </a>
                      {/* more inner pages*/}
                    </li>
                    <li className="nav-item">
                      <a
                        className="nav-link"
                        href="app/e-commerce/checkout.html"
                        aria-expanded="false"
                      >
                        <div className="d-flex align-items-center">
                          <span className="nav-link-text ps-1">Checkout</span>
                        </div>
                      </a>
                      {/* more inner pages*/}
                    </li>
                    <li className="nav-item">
                      <a
                        className="nav-link"
                        href="app/e-commerce/billing.html"
                        aria-expanded="false"
                      >
                        <div className="d-flex align-items-center">
                          <span className="nav-link-text ps-1">Billing</span>
                        </div>
                      </a>
                      {/* more inner pages*/}
                    </li>
                    <li className="nav-item">
                      <a
                        className="nav-link"
                        href="app/e-commerce/invoice.html"
                        aria-expanded="false"
                      >
                        <div className="d-flex align-items-center">
                          <span className="nav-link-text ps-1">Invoice</span>
                        </div>
                      </a>
                      {/* more inner pages*/}
                    </li>
                  </ul>
                </li>
                <li className="nav-item">
                  {/* label*/}
                  <div className="row navbar-vertical-label-wrapper mt-3 mb-2">
                    <div className="col-auto navbar-vertical-label">Pages</div>
                    <div className="col ps-0">
                      <hr className="mb-0 navbar-vertical-divider" />
                    </div>
                  </div>
                  {/* parent pages*/}
                  <a
                    className="nav-link dropdown-indicator"
                    href="#authentication"
                    role="button"
                    data-bs-toggle="collapse"
                    aria-expanded="false"
                    aria-controls="authentication"
                  >
                    <div className="d-flex align-items-center">
                      <span className="nav-link-icon">
                        <span className="fas fa-lock" />
                      </span>
                      <span className="nav-link-text ps-1">Authentication</span>
                    </div>
                  </a>
                  <ul className="nav collapse false" id="authentication">
                    <li className="nav-item">
                      <a
                        className="nav-link dropdown-indicator"
                        href="#card"
                        data-bs-toggle="collapse"
                        aria-expanded="false"
                        aria-controls="authentication"
                      >
                        <div className="d-flex align-items-center">
                          <span className="nav-link-text ps-1">Auth</span>
                        </div>
                      </a>
                      {/* more inner pages*/}
                      <ul className="nav collapse false" id="card">
                        <li className="nav-item">
                          <Link className="nav-link" to="/">
                            <div className="d-flex align-items-center">
                              <span className="nav-link-text ps-1">Login</span>
                            </div>
                          </Link>
                          {/* more inner pages*/}
                        </li>
                        <li className="nav-item">
                          <Link className="nav-link" to="/logout">
                            <div className="d-flex align-items-center">
                              <span className="nav-link-text ps-1">Logout</span>
                            </div>
                          </Link>
                          {/* more inner pages*/}
                        </li>
                        <li className="nav-item">
                          <Link className="nav-link" to="/register">
                            <div className="d-flex align-items-center">
                              <span className="nav-link-text ps-1">
                                Register
                              </span>
                            </div>
                          </Link>
                          {/* more inner pages*/}
                        </li>
                        <li className="nav-item">
                          <Link className="nav-link" to="/forgotpassword">
                            <div className="d-flex align-items-center">
                              <span className="nav-link-text ps-1">
                                Forgot password
                              </span>
                            </div>
                          </Link>
                          {/* more inner pages*/}
                        </li>
                        <li className="nav-item">
                          <Link className="nav-link" to="/confirmmail">
                            <div className="d-flex align-items-center">
                              <span className="nav-link-text ps-1">
                                Confirm mail
                              </span>
                            </div>
                          </Link>
                          {/* more inner pages*/}
                        </li>
                        <li className="nav-item">
                          <Link className="nav-link" to="/resetpassword">
                            <div className="d-flex align-items-center">
                              <span className="nav-link-text ps-1">
                                Reset password
                              </span>
                            </div>
                          </Link>
                          {/* more inner pages*/}
                        </li>
                        <li className="nav-item">
                          <Link className="nav-link" to="/lockscreen">
                            <div className="d-flex align-items-center">
                              <span className="nav-link-text ps-1">
                                Lock screen
                              </span>
                            </div>
                          </Link>
                          {/* more inner pages*/}
                        </li>
                      </ul>
                    </li>
                  </ul>
                  {/* parent pages*/}
                  <a
                    className="nav-link dropdown-indicator"
                    href="#user"
                    role="button"
                    data-bs-toggle="collapse"
                    aria-expanded="false"
                    aria-controls="user"
                  >
                    <div className="d-flex align-items-center">
                      <span className="nav-link-icon">
                        <span className="fas fa-user" />
                      </span>
                      <span className="nav-link-text ps-1">User</span>
                    </div>
                  </a>
                  <ul className="nav collapse false" id="user">
                    <li className="nav-item">
                      <a
                        className="nav-link"
                        href="pages/user/profile.html"
                        aria-expanded="false"
                      >
                        <div className="d-flex align-items-center">
                          <span className="nav-link-text ps-1">Profile</span>
                        </div>
                      </a>
                      {/* more inner pages*/}
                    </li>
                    <li className="nav-item">
                      <a
                        className="nav-link"
                        href="pages/user/settings.html"
                        aria-expanded="false"
                      >
                        <div className="d-flex align-items-center">
                          <span className="nav-link-text ps-1">Settings</span>
                        </div>
                      </a>
                      {/* more inner pages*/}
                    </li>
                  </ul>
                </li>
                <li className="nav-item">
                  {/* label*/}
                  <div className="row navbar-vertical-label-wrapper mt-3 mb-2">
                    <div className="col-auto navbar-vertical-label">Logs</div>
                    <div className="col ps-0">
                      <hr className="mb-0 navbar-vertical-divider" />
                    </div>
                  </div>
                  <a
                    className="nav-link"
                    href="changelog.html"
                    role="button"
                    aria-expanded="false"
                  >
                    <div className="d-flex align-items-center">
                      <span className="nav-link-icon">
                        <span className="fas fa-code-branch" />
                      </span>
                      <span className="nav-link-text ps-1">Log</span>
                    </div>
                  </a>
                </li>
              </ul>
            </div>
          </div>
        </nav>
        {isAdmin ? (
          <div className="content">
            {/* My Nav Bar Code */}
            <nav className="navbar navbar-light navbar-glass navbar-top navbar-expand">
              <button
                className="btn navbar-toggler-humburger-icon navbar-toggler me-1 me-sm-3"
                type="button"
                data-bs-toggle="collapse"
                data-bs-target="#navbarVerticalCollapse"
                aria-controls="navbarVerticalCollapse"
                aria-expanded="false"
                aria-label="Toggle Navigation"
              >
                <span className="navbar-toggle-icon">
                  <span className="toggle-line" />
                </span>
              </button>
              <a className="navbar-brand me-1 me-sm-3" href="index.html">
                <div className="d-flex align-items-center">
                  <span className="font-sans-serif">Dashboard</span>
                </div>
              </a>
              <ul className="navbar-nav align-items-center d-none d-lg-block">
                <li className="nav-item">
                  <div
                    className="search-box"
                    data-list='{"valueNames":["title"]}'
                  >
                    <form
                      className="position-relative"
                      data-bs-toggle="search"
                      data-bs-display="static"
                    >
                      <input
                        className="form-control search-input fuzzy-search"
                        type="search"
                        placeholder="Search..."
                        aria-label="Search"
                      />
                      <span className="fas fa-search search-box-icon" />
                    </form>
                    <div
                      className="btn-close-falcon-container position-absolute end-0 top-50 translate-middle shadow-none"
                      data-bs-dismiss="search"
                    >
                      <div className="btn-close-falcon" aria-label="Close" />
                    </div>
                    <div className="dropdown-menu border font-base start-0 mt-2 py-0 overflow-hidden w-100">
                      <div
                        className="scrollbar list py-3"
                        style={{ maxHeight: "24rem" }}
                      >
                        <h6 className="dropdown-header fw-medium text-uppercase px-card fs--2 pt-0 pb-2">
                          Recently Browsed
                        </h6>
                        <a
                          className="dropdown-item fs--1 px-card py-1 hover-primary"
                          href="app/events/event-detail.html"
                        >
                          <div className="d-flex align-items-center">
                            <span className="fas fa-circle me-2 text-300 fs--2" />
                            <div className="fw-normal title">
                              Pages{" "}
                              <span
                                className="fas fa-chevron-right mx-1 text-500 fs--2"
                                data-fa-transform="shrink-2"
                              />{" "}
                              Events
                            </div>
                          </div>
                        </a>
                        <a
                          className="dropdown-item fs--1 px-card py-1 hover-primary"
                          href="app/e-commerce/customers.html"
                        >
                          <div className="d-flex align-items-center">
                            <span className="fas fa-circle me-2 text-300 fs--2" />
                            <div className="fw-normal title">
                              E-commerce{" "}
                              <span
                                className="fas fa-chevron-right mx-1 text-500 fs--2"
                                data-fa-transform="shrink-2"
                              />{" "}
                              Customers
                            </div>
                          </div>
                        </a>
                        <hr className="bg-200 dark__bg-900" />
                        <h6 className="dropdown-header fw-medium text-uppercase px-card fs--2 pt-0 pb-2">
                          Suggested Filter
                        </h6>
                        <a
                          className="dropdown-item px-card py-1 fs-0"
                          href="app/e-commerce/customers.html"
                        >
                          <div className="d-flex align-items-center">
                            <span className="badge fw-medium text-decoration-none me-2 badge-soft-warning">
                              customers:
                            </span>
                            <div className="flex-1 fs--1 title">
                              All customers list
                            </div>
                          </div>
                        </a>
                        <a
                          className="dropdown-item px-card py-1 fs-0"
                          href="app/events/event-detail.html"
                        >
                          <div className="d-flex align-items-center">
                            <span className="badge fw-medium text-decoration-none me-2 badge-soft-success">
                              events:
                            </span>
                            <div className="flex-1 fs--1 title">
                              Latest events in current month
                            </div>
                          </div>
                        </a>
                        <a
                          className="dropdown-item px-card py-1 fs-0"
                          href="app/e-commerce/product/product-grid.html"
                        >
                          <div className="d-flex align-items-center">
                            <span className="badge fw-medium text-decoration-none me-2 badge-soft-info">
                              products:
                            </span>
                            <div className="flex-1 fs--1 title">
                              Most popular products
                            </div>
                          </div>
                        </a>
                        <hr className="bg-200 dark__bg-900" />
                        <h6 className="dropdown-header fw-medium text-uppercase px-card fs--2 pt-0 pb-2">
                          Files
                        </h6>
                        <a className="dropdown-item px-card py-2" href="#!">
                          <div className="d-flex align-items-center">
                            <div className="file-thumbnail me-2">
                              <img
                                className="border h-100 w-100 fit-cover rounded-3"
                                src="/img/products/3-thumb.png"
                                alt=""
                              />
                            </div>
                            <div className="flex-1">
                              <h6 className="mb-0 title">iPhone</h6>
                              <p className="fs--2 mb-0 d-flex">
                                <span className="fw-semi-bold">Antony</span>
                                <span className="fw-medium text-600 ms-2">
                                  27 Sep at 10:30 AM
                                </span>
                              </p>
                            </div>
                          </div>
                        </a>
                        <a className="dropdown-item px-card py-2" href="#!">
                          <div className="d-flex align-items-center">
                            <div className="file-thumbnail me-2">
                              <img
                                className="img-fluid"
                                src="/img/icons/zip.png"
                                alt=""
                              />
                            </div>
                            <div className="flex-1">
                              <h6 className="mb-0 title">Falcon v1.8.2</h6>
                              <p className="fs--2 mb-0 d-flex">
                                <span className="fw-semi-bold">John</span>
                                <span className="fw-medium text-600 ms-2">
                                  30 Sep at 12:30 PM
                                </span>
                              </p>
                            </div>
                          </div>
                        </a>
                        <hr className="bg-200 dark__bg-900" />
                        <h6 className="dropdown-header fw-medium text-uppercase px-card fs--2 pt-0 pb-2">
                          Members
                        </h6>
                        <a
                          className="dropdown-item px-card py-2"
                          href="pages/user/profile.html"
                        >
                          <div className="d-flex align-items-center">
                            <div className="avatar avatar-l status-online me-2">
                              <img
                                className="rounded-circle"
                                src="/img/team/1.jpg"
                                alt=""
                              />
                            </div>
                            <div className="flex-1">
                              <h6 className="mb-0 title">Anna Karinina</h6>
                              <p className="fs--2 mb-0 d-flex">
                                Technext Limited
                              </p>
                            </div>
                          </div>
                        </a>
                        <a
                          className="dropdown-item px-card py-2"
                          href="pages/user/profile.html"
                        >
                          <div className="d-flex align-items-center">
                            <div className="avatar avatar-l me-2">
                              <img
                                className="rounded-circle"
                                src="/img/team/2.jpg"
                                alt=""
                              />
                            </div>
                            <div className="flex-1">
                              <h6 className="mb-0 title">Antony Hopkins</h6>
                              <p className="fs--2 mb-0 d-flex">Brain Trust</p>
                            </div>
                          </div>
                        </a>
                        <a
                          className="dropdown-item px-card py-2"
                          href="pages/user/profile.html"
                        >
                          <div className="d-flex align-items-center">
                            <div className="avatar avatar-l me-2">
                              <img
                                className="rounded-circle"
                                src="/img/team/3.jpg"
                                alt=""
                              />
                            </div>
                            <div className="flex-1">
                              <h6 className="mb-0 title">Emma Watson</h6>
                              <p className="fs--2 mb-0 d-flex">Google</p>
                            </div>
                          </div>
                        </a>
                      </div>
                      <div className="text-center mt-n3">
                        <p className="fallback fw-bold fs-1 d-none">
                          No Result Found.
                        </p>
                      </div>
                    </div>
                  </div>
                </li>
              </ul>
              <ul className="navbar-nav navbar-nav-icons ms-auto flex-row align-items-center">
                <li className="nav-item">
                  <div className="theme-control-toggle fa-icon-wait px-2">
                    <input
                      className="form-check-input ms-0 theme-control-toggle-input"
                      id="themeControlToggle"
                      type="checkbox"
                      data-theme-control="theme"
                      defaultValue="dark"
                    />
                    <label
                      className="mb-0 theme-control-toggle-label theme-control-toggle-light"
                      htmlFor="themeControlToggle"
                      data-bs-toggle="tooltip"
                      data-bs-placement="left"
                      title="Switch to light theme"
                    >
                      <span className="fas fa-sun fs-0" />
                    </label>
                    <label
                      className="mb-0 theme-control-toggle-label theme-control-toggle-dark"
                      htmlFor="themeControlToggle"
                      data-bs-toggle="tooltip"
                      data-bs-placement="left"
                      title="Switch to dark theme"
                    >
                      <span className="fas fa-moon fs-0" />
                    </label>
                  </div>
                </li>
                <li className="nav-item">
                  <a
                    className="nav-link px-0 notification-indicator notification-indicator-warning notification-indicator-fill fa-icon-wait"
                    href="app/e-commerce/shopping-cart.html"
                  >
                    <span
                      className="fas fa-shopping-cart"
                      data-fa-transform="shrink-7"
                      style={{ fontSize: 33 }}
                    />
                    <span className="notification-indicator-number">1</span>
                  </a>
                </li>
                <li className="nav-item dropdown">
                  <a
                    className="nav-link notification-indicator notification-indicator-primary px-0 fa-icon-wait"
                    id="navbarDropdownNotification"
                    href="#"
                    role="button"
                    data-bs-toggle="dropdown"
                    aria-haspopup="true"
                    aria-expanded="false"
                  >
                    <span
                      className="fas fa-bell"
                      data-fa-transform="shrink-6"
                      style={{ fontSize: 33 }}
                    />
                  </a>
                  <div
                    className="dropdown-menu dropdown-menu-end dropdown-menu-card dropdown-menu-notification"
                    aria-labelledby="navbarDropdownNotification"
                  >
                    <div className="card card-notification shadow-none">
                      <div className="card-header">
                        <div className="row justify-content-between align-items-center">
                          <div className="col-auto">
                            <h6 className="card-header-title mb-0">
                              Notifications
                            </h6>
                          </div>
                          <div className="col-auto ps-0 ps-sm-3">
                            <a className="card-link fw-normal" href="#">
                              Mark all as read
                            </a>
                          </div>
                        </div>
                      </div>
                      <div
                        className="scrollbar-overlay"
                        style={{ maxHeight: "19rem" }}
                      >
                        <div className="list-group list-group-flush fw-normal fs--1">
                          <div className="list-group-title border-bottom">
                            NEW
                          </div>
                          <div className="list-group-item">
                            <a
                              className="notification notification-flush notification-unread"
                              href="#!"
                            >
                              <div className="notification-avatar">
                                <div className="avatar avatar-2xl me-3">
                                  <img
                                    className="rounded-circle"
                                    src="/img/team/1-thumb.png"
                                    alt=""
                                  />
                                </div>
                              </div>
                              <div className="notification-body">
                                <p className="mb-1">
                                  <strong>Emma Watson</strong> replied to your
                                  comment : &quot;Hello world 😍
                                </p>
                                <span className="notification-time">
                                  <span
                                    className="me-2"
                                    role="img"
                                    aria-label="Emoji"
                                  >
                                    💬
                                  </span>
                                  Just now
                                </span>
                              </div>
                            </a>
                          </div>
                          <div className="list-group-item">
                            <a
                              className="notification notification-flush notification-unread"
                              href="#!"
                            >
                              <div className="notification-avatar">
                                <div className="avatar avatar-2xl me-3">
                                  <div className="avatar-name rounded-circle">
                                    <span>AB</span>
                                  </div>
                                </div>
                              </div>
                              <div className="notification-body">
                                <p className="mb-1">
                                  <strong>Albert Brooks</strong> reacted to{" "}
                                  <strong>Mia Khalifa&apos;s</strong> status
                                </p>
                                <span className="notification-time">
                                  <span className="me-2 fab fa-gratipay text-danger" />
                                  9hr
                                </span>
                              </div>
                            </a>
                          </div>
                          <div className="list-group-title border-bottom">
                            EARLIER
                          </div>
                          <div className="list-group-item">
                            <a
                              className="notification notification-flush"
                              href="#!"
                            >
                              <div className="notification-avatar">
                                <div className="avatar avatar-2xl me-3">
                                  <img
                                    className="rounded-circle"
                                    src="/img/icons/weather-sm.jpg"
                                    alt=""
                                  />
                                </div>
                              </div>
                              <div className="notification-body">
                                <p className="mb-1">
                                  The forecast today shows a low of 20℃ in
                                  California. See today&apos;s weather.
                                </p>
                                <span className="notification-time">
                                  <span
                                    className="me-2"
                                    role="img"
                                    aria-label="Emoji"
                                  >
                                    🌤️
                                  </span>
                                  1d
                                </span>
                              </div>
                            </a>
                          </div>
                          <div className="list-group-item">
                            <a
                              className="border-bottom-0 notification-unread  notification notification-flush"
                              href="#!"
                            >
                              <div className="notification-avatar">
                                <div className="avatar avatar-xl me-3">
                                  <img
                                    className="rounded-circle"
                                    src="/img/logos/oxford.png"
                                    alt=""
                                  />
                                </div>
                              </div>
                              <div className="notification-body">
                                <p className="mb-1">
                                  <strong>University of Oxford</strong> created
                                  an event : &quot;Causal Inference Hilary 2019
                                </p>
                                <span className="notification-time">
                                  <span
                                    className="me-2"
                                    role="img"
                                    aria-label="Emoji"
                                  >
                                    ✌️
                                  </span>
                                  1w
                                </span>
                              </div>
                            </a>
                          </div>
                          <div className="list-group-item">
                            <a
                              className="border-bottom-0 notification notification-flush"
                              href="#!"
                            >
                              <div className="notification-avatar">
                                <div className="avatar avatar-xl me-3">
                                  <img
                                    className="rounded-circle"
                                    src="/img/team/10.jpg"
                                    alt=""
                                  />
                                </div>
                              </div>
                              <div className="notification-body">
                                <p className="mb-1">
                                  <strong>James Cameron</strong> invited to join
                                  the group: United Nations International
                                  Children&apos;s Fund
                                </p>
                                <span className="notification-time">
                                  <span
                                    className="me-2"
                                    role="img"
                                    aria-label="Emoji"
                                  >
                                    🙋‍
                                  </span>
                                  2d
                                </span>
                              </div>
                            </a>
                          </div>
                        </div>
                      </div>
                      <div className="card-footer text-center border-top">
                        <a
                          className="card-link d-block"
                          href="app/social/notifications.html"
                        >
                          View all
                        </a>
                      </div>
                    </div>
                  </div>
                </li>
                <li className="nav-item dropdown">
                  <a
                    className="nav-link pe-0"
                    id="navbarDropdownUser"
                    href="#"
                    role="button"
                    data-bs-toggle="dropdown"
                    aria-haspopup="true"
                    aria-expanded="false"
                  >
                    <div className="avatar avatar-xl">
                      <img
                        className="rounded-circle"
                        src="img/bankks.png"
                        alt="Team"
                      />
                    </div>
                  </a>
                  <div
                    className="dropdown-menu dropdown-menu-end py-0"
                    aria-labelledby="navbarDropdownUser"
                  >
                    <div className="bg-white dark__bg-1000 rounded-2 py-2">
                      <a
                        className="dropdown-item fw-bold text-danger"
                        href="#!"
                      >
                        <span>Change Admin Password</span>
                      </a>
                      <div className="dropdown-divider" />
                      <a className="dropdown-item" href="#!">
                        Set status
                      </a>
                      <a
                        className="dropdown-item"
                        href="pages/user/profile.html"
                      >
                        Profile &amp; account
                      </a>
                      <a className="dropdown-item" href="#!">
                        Feedback
                      </a>
                      <div className="dropdown-divider" />
                      <a
                        className="dropdown-item"
                        href="pages/user/settings.html"
                      >
                        Settings
                      </a>
                      <Link
                        className="dropdown-item"
                        onClick={handleLogout}
                        to="/logout"
                      >
                        Logout
                      </Link>
                    </div>
                  </div>
                </li>
              </ul>
            </nav>
            <footer className="footer">
              <div className="row g-0 justify-content-between fs--1 mt-4 mb-3">
                <div className="col-12 col-sm-auto text-center">
                  <p className="mb-0 text-600">
                    Powered by <strong>Dynamic Order Management System</strong>{" "}
                    <span className="d-none d-sm-inline-block">| </span>
                    <br className="d-sm-none" /> 2025 ©{" "}
                    <a href="https://github.com/YogTandel">YOG TANDEL</a>
                  </p>
                </div>
              </div>
            </footer>
            <div className="container mt-2">
              <h3>Admin Content</h3>
              <div id="tableExample2">
                <div className="d-flex justify-content-between align-items-center mb-3">
                  <h5 className="mb-0">User Table</h5>
                  {role === "superadmin" && (
                    <button
                      className="btn btn-primary"
                      onClick={handleCreateAdmin}
                    >
                      Create Admin
                    </button>
                  )}
                </div>
                <div className="table-responsive scrollbar">
                  <table className="table table-bordered table-striped fs--1 mb-0">
                    <thead className="bg-200 text-900">
                      <tr>
                        <th>Email</th>
                        <th>Date</th>
                        <th>Role</th>
                        <th>Permission</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {currentUsers.map((user, index) => (
                        <tr key={index}>
                          <td>{user.email}</td>
                          <td>
                            {user.date
                              ? new Date(user.date).toISOString().split("T")[0]
                              : "N/A"}
                          </td>
                          <td>{user.role ? user.role : "No Role"}</td>
                          <td>
                            {role === "superadmin" ? (
                              <button
                                className="btn btn-sm btn-primary"
                                onClick={() => togglePageModal(user)}
                              >
                                Select Role
                              </button>
                            ) : (
                              <i className="fas fa-lock"></i>
                            )}
                          </td>
                          <td>
                            {role === "superadmin" && (
                              <button className="btn btn-sm btn-danger">
                                <i className="fas fa-ban me-1"></i>
                                {/* Block */}
                              </button>
                            )}
                            <span style={{ margin: "0 8px" }}></span>
                            {role === "admin" ||
                              (role === "superadmin" && (
                                <button
                                  className="btn btn-sm btn-info"
                                  onClick={() =>
                                    copyCredentials(
                                      user.email,
                                      user.password,
                                      user.role
                                    )
                                  }
                                >
                                  <i className="fas fa-copy me-1"></i>
                                  {/* Copy Credentials */}
                                </button>
                              ))}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="d-flex flex-column align-items-end mt-3">
                  <div className="w-100 border-top mb-2"></div>
                  <div className="d-inline-flex align-items-center border rounded p-2">
                    <button
                      className="btn btn-sm btn-outline-secondary me-2"
                      onClick={handlePrev}
                      disabled={currentPage === 1}
                    >
                      <i className="fas fa-chevron-left"></i>
                    </button>
                    <ul className="pagination mb-0">
                      {Array.from({ length: totalPages }, (_, index) => (
                        <li
                          key={index + 1}
                          className={`page-item ${
                            currentPage === index + 1 ? "active" : ""
                          }`}
                        >
                          <button
                            className="page-link"
                            onClick={() => handlePageChange(index + 1)}
                          >
                            {index + 1}
                          </button>
                        </li>
                      ))}
                    </ul>
                    <button
                      className="btn btn-sm btn-outline-secondary ms-2"
                      onClick={handleNext}
                      disabled={currentPage === totalPages}
                    >
                      <i className="fas fa-chevron-right"></i>
                    </button>
                  </div>
                </div>
              </div>
            </div>
            {showPageModal && (
              <div className="modal d-block" tabIndex="-1" role="dialog">
                <div className="modal-dialog" role="document">
                  <div className="modal-content">
                    <div className="modal-header">
                      <h5 className="modal-title">
                        Select Pages for {currentUser?.email}
                      </h5>
                      <button
                        type="button"
                        className="close"
                        onClick={() => setShowPageModal(false)} // Close modal when clicked
                      >
                        <span>&times;</span>
                      </button>
                    </div>
                    <div className="modal-body">
                      <form>
                        <div className="form-group">
                          <div className="d-flex justify-content-between">
                            <label>Select Pages</label>
                            <div>
                              {/* List of checkboxes for different pages */}
                              <div className="form-check">
                                <input
                                  type="checkbox"
                                  className="form-check-input"
                                  checked={selectedPages.includes("Dashboard")}
                                  onChange={() => togglePage("Dashboard")}
                                />
                                <label className="form-check-label">
                                  Dashboard
                                </label>
                              </div>
                              <div className="form-check">
                                <input
                                  type="checkbox"
                                  className="form-check-input"
                                  checked={selectedPages.includes("Users")}
                                  onChange={() => togglePage("Users")}
                                />
                                <label className="form-check-label">
                                  Users
                                </label>
                              </div>
                              <div className="form-check">
                                <input
                                  type="checkbox"
                                  className="form-check-input"
                                  checked={selectedPages.includes("Reports")}
                                  onChange={() => togglePage("Reports")}
                                />
                                <label className="form-check-label">
                                  Reports
                                </label>
                              </div>
                              <div className="form-check">
                                <input
                                  type="checkbox"
                                  className="form-check-input"
                                  checked={selectedPages.includes("Settings")}
                                  onChange={() => togglePage("Settings")}
                                />
                                <label className="form-check-label">
                                  Settings
                                </label>
                              </div>
                              {/* Add more pages as needed */}
                            </div>
                          </div>
                        </div>
                        <button
                          type="button"
                          className="btn btn-primary mt-3"
                          onClick={handleSavePage} // Save pages for the current user
                        >
                          Save Pages
                        </button>
                      </form>
                    </div>
                  </div>
                </div>
              </div>
            )}
            {/* Modal for Creating Admin */}
            {showModal && (
              <div className="modal d-block" tabIndex="-1" role="dialog">
                <div className="modal-dialog" role="document">
                  <div className="modal-content">
                    <div className="modal-header">
                      <h5 className="modal-title">Create Admin</h5>
                      <button
                        type="button"
                        className="close"
                        onClick={() => setShowModal(false)}
                      >
                        <span>&times;</span>
                      </button>
                    </div>
                    <div className="modal-body">
                      <form>
                        <div className="form-group">
                          <label>Email</label>
                          <input
                            type="email"
                            className="form-control"
                            value={newAdmin.email}
                            onChange={(e) =>
                              setNewAdmin({
                                ...newAdmin,
                                email: e.target.value,
                              })
                            }
                          />
                        </div>
                        <div className="form-group mt-3">
                          <label>Password</label>
                          <div className="input-group">
                            <input
                              type={showPassword ? "text" : "password"}
                              value={newAdmin.password}
                              onChange={(e) =>
                                setNewAdmin({
                                  ...newAdmin,
                                  password: e.target.value,
                                })
                              }
                              required
                            />
                            <span
                              className="input-group-text"
                              style={{ cursor: "pointer" }}
                              onClick={handlePasswordToggle}
                            >
                              {showPassword ? (
                                <i className="fas fa-eye-slash"></i>
                              ) : (
                                <i className="fas fa-eye"></i>
                              )}
                            </span>
                          </div>
                          {/* Validation Messages */}
                          <small className="form-text text-muted">
                            <ul className="list-group list-group-flush mt-2">
                              <li
                                className={`list-group-item ${
                                  passwordValidation.lengthValid
                                    ? "text-success"
                                    : "text-danger"
                                }`}
                              >
                                {passwordValidation.lengthValid ? (
                                  <i className="fas fa-check-circle me-2 text-success"></i>
                                ) : (
                                  <i className="fas fa-times-circle me-2 text-danger"></i>
                                )}
                                Password must be at least 6 characters long
                              </li>
                              <li
                                className={`list-group-item ${
                                  passwordValidation.lowerCaseValid
                                    ? "text-success"
                                    : "text-danger"
                                }`}
                              >
                                {passwordValidation.lowerCaseValid ? (
                                  <i className="fas fa-check-circle me-2 text-success"></i>
                                ) : (
                                  <i className="fas fa-times-circle me-2 text-danger"></i>
                                )}
                                Password must include at least one lowercase
                                letter
                              </li>
                              <li
                                className={`list-group-item ${
                                  passwordValidation.upperCaseValid
                                    ? "text-success"
                                    : "text-danger"
                                }`}
                              >
                                {passwordValidation.upperCaseValid ? (
                                  <i className="fas fa-check-circle me-2 text-success"></i>
                                ) : (
                                  <i className="fas fa-times-circle me-2 text-danger"></i>
                                )}
                                Password must include at least one uppercase
                                letter
                              </li>
                              <li
                                className={`list-group-item ${
                                  passwordValidation.digitValid
                                    ? "text-success"
                                    : "text-danger"
                                }`}
                              >
                                {passwordValidation.digitValid ? (
                                  <i className="fas fa-check-circle me-2 text-success"></i>
                                ) : (
                                  <i className="fas fa-times-circle me-2 text-danger"></i>
                                )}
                                Password must include at least one digit
                              </li>
                            </ul>
                          </small>
                        </div>
                        <div className="form-group mt-3">
                          <label>Role</label>
                          <input
                            type="text"
                            className="form-control"
                            value={newAdmin.role}
                            onChange={(e) =>
                              setNewAdmin({
                                ...newAdmin,
                                role: e.target.value,
                              })
                            }
                            placeholder="Enter role (e.g., admin, manager, cook)"
                          />
                        </div>
                        <div className="form-group mt-3">
                          <label>Date</label>
                          <input
                            type="text"
                            className="form-control"
                            value={
                              newAdmin.date ||
                              new Date().toISOString().split("T")[0]
                            }
                            readOnly
                          />
                        </div>
                        <button
                          type="button"
                          className="btn btn-primary mt-3"
                          onClick={handleSaveAdmin}
                        >
                          Save Admin
                        </button>
                      </form>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        ) : (
          /* Default Page */
          <div className="content">
            <nav className="navbar navbar-light navbar-glass navbar-top navbar-expand">
              <button
                className="btn navbar-toggler-humburger-icon navbar-toggler me-1 me-sm-3"
                type="button"
                data-bs-toggle="collapse"
                data-bs-target="#navbarVerticalCollapse"
                aria-controls="navbarVerticalCollapse"
                aria-expanded="false"
                aria-label="Toggle Navigation"
              >
                <span className="navbar-toggle-icon">
                  <span className="toggle-line" />
                </span>
              </button>
              <a className="navbar-brand me-1 me-sm-3" href="index.html">
                <div className="d-flex align-items-center">
                  <span className="font-sans-serif">Dashboard</span>
                </div>
              </a>
              <ul className="navbar-nav align-items-center d-none d-lg-block">
                <li className="nav-item">
                  <div
                    className="search-box"
                    data-list='{"valueNames":["title"]}'
                  >
                    <form
                      className="position-relative"
                      data-bs-toggle="search"
                      data-bs-display="static"
                    >
                      <input
                        className="form-control search-input fuzzy-search"
                        type="search"
                        placeholder="Search..."
                        aria-label="Search"
                      />
                      <span className="fas fa-search search-box-icon" />
                    </form>
                    <div
                      className="btn-close-falcon-container position-absolute end-0 top-50 translate-middle shadow-none"
                      data-bs-dismiss="search"
                    >
                      <div className="btn-close-falcon" aria-label="Close" />
                    </div>
                    <div className="dropdown-menu border font-base start-0 mt-2 py-0 overflow-hidden w-100">
                      <div
                        className="scrollbar list py-3"
                        style={{ maxHeight: "24rem" }}
                      >
                        <h6 className="dropdown-header fw-medium text-uppercase px-card fs--2 pt-0 pb-2">
                          Recently Browsed
                        </h6>
                        <a
                          className="dropdown-item fs--1 px-card py-1 hover-primary"
                          href="app/events/event-detail.html"
                        >
                          <div className="d-flex align-items-center">
                            <span className="fas fa-circle me-2 text-300 fs--2" />
                            <div className="fw-normal title">
                              Pages{" "}
                              <span
                                className="fas fa-chevron-right mx-1 text-500 fs--2"
                                data-fa-transform="shrink-2"
                              />{" "}
                              Events
                            </div>
                          </div>
                        </a>
                        <a
                          className="dropdown-item fs--1 px-card py-1 hover-primary"
                          href="app/e-commerce/customers.html"
                        >
                          <div className="d-flex align-items-center">
                            <span className="fas fa-circle me-2 text-300 fs--2" />
                            <div className="fw-normal title">
                              E-commerce{" "}
                              <span
                                className="fas fa-chevron-right mx-1 text-500 fs--2"
                                data-fa-transform="shrink-2"
                              />{" "}
                              Customers
                            </div>
                          </div>
                        </a>
                        <hr className="bg-200 dark__bg-900" />
                        <h6 className="dropdown-header fw-medium text-uppercase px-card fs--2 pt-0 pb-2">
                          Suggested Filter
                        </h6>
                        <a
                          className="dropdown-item px-card py-1 fs-0"
                          href="app/e-commerce/customers.html"
                        >
                          <div className="d-flex align-items-center">
                            <span className="badge fw-medium text-decoration-none me-2 badge-soft-warning">
                              customers:
                            </span>
                            <div className="flex-1 fs--1 title">
                              All customers list
                            </div>
                          </div>
                        </a>
                        <a
                          className="dropdown-item px-card py-1 fs-0"
                          href="app/events/event-detail.html"
                        >
                          <div className="d-flex align-items-center">
                            <span className="badge fw-medium text-decoration-none me-2 badge-soft-success">
                              events:
                            </span>
                            <div className="flex-1 fs--1 title">
                              Latest events in current month
                            </div>
                          </div>
                        </a>
                        <a
                          className="dropdown-item px-card py-1 fs-0"
                          href="app/e-commerce/product/product-grid.html"
                        >
                          <div className="d-flex align-items-center">
                            <span className="badge fw-medium text-decoration-none me-2 badge-soft-info">
                              products:
                            </span>
                            <div className="flex-1 fs--1 title">
                              Most popular products
                            </div>
                          </div>
                        </a>
                        <hr className="bg-200 dark__bg-900" />
                        <h6 className="dropdown-header fw-medium text-uppercase px-card fs--2 pt-0 pb-2">
                          Files
                        </h6>
                        <a className="dropdown-item px-card py-2" href="#!">
                          <div className="d-flex align-items-center">
                            <div className="file-thumbnail me-2">
                              <img
                                className="border h-100 w-100 fit-cover rounded-3"
                                src="/img/products/3-thumb.png"
                                alt=""
                              />
                            </div>
                            <div className="flex-1">
                              <h6 className="mb-0 title">iPhone</h6>
                              <p className="fs--2 mb-0 d-flex">
                                <span className="fw-semi-bold">Antony</span>
                                <span className="fw-medium text-600 ms-2">
                                  27 Sep at 10:30 AM
                                </span>
                              </p>
                            </div>
                          </div>
                        </a>
                        <a className="dropdown-item px-card py-2" href="#!">
                          <div className="d-flex align-items-center">
                            <div className="file-thumbnail me-2">
                              <img
                                className="img-fluid"
                                src="/img/icons/zip.png"
                                alt=""
                              />
                            </div>
                            <div className="flex-1">
                              <h6 className="mb-0 title">Falcon v1.8.2</h6>
                              <p className="fs--2 mb-0 d-flex">
                                <span className="fw-semi-bold">John</span>
                                <span className="fw-medium text-600 ms-2">
                                  30 Sep at 12:30 PM
                                </span>
                              </p>
                            </div>
                          </div>
                        </a>
                        <hr className="bg-200 dark__bg-900" />
                        <h6 className="dropdown-header fw-medium text-uppercase px-card fs--2 pt-0 pb-2">
                          Members
                        </h6>
                        <a
                          className="dropdown-item px-card py-2"
                          href="pages/user/profile.html"
                        >
                          <div className="d-flex align-items-center">
                            <div className="avatar avatar-l status-online me-2">
                              <img
                                className="rounded-circle"
                                src="/img/team/1.jpg"
                                alt=""
                              />
                            </div>
                            <div className="flex-1">
                              <h6 className="mb-0 title">Anna Karinina</h6>
                              <p className="fs--2 mb-0 d-flex">
                                Technext Limited
                              </p>
                            </div>
                          </div>
                        </a>
                        <a
                          className="dropdown-item px-card py-2"
                          href="pages/user/profile.html"
                        >
                          <div className="d-flex align-items-center">
                            <div className="avatar avatar-l me-2">
                              <img
                                className="rounded-circle"
                                src="/img/team/2.jpg"
                                alt=""
                              />
                            </div>
                            <div className="flex-1">
                              <h6 className="mb-0 title">Antony Hopkins</h6>
                              <p className="fs--2 mb-0 d-flex">Brain Trust</p>
                            </div>
                          </div>
                        </a>
                        <a
                          className="dropdown-item px-card py-2"
                          href="pages/user/profile.html"
                        >
                          <div className="d-flex align-items-center">
                            <div className="avatar avatar-l me-2">
                              <img
                                className="rounded-circle"
                                src="/img/team/3.jpg"
                                alt=""
                              />
                            </div>
                            <div className="flex-1">
                              <h6 className="mb-0 title">Emma Watson</h6>
                              <p className="fs--2 mb-0 d-flex">Google</p>
                            </div>
                          </div>
                        </a>
                      </div>
                      <div className="text-center mt-n3">
                        <p className="fallback fw-bold fs-1 d-none">
                          No Result Found.
                        </p>
                      </div>
                    </div>
                  </div>
                </li>
              </ul>
              <ul className="navbar-nav navbar-nav-icons ms-auto flex-row align-items-center">
                <li className="nav-item">
                  <div className="theme-control-toggle fa-icon-wait px-2">
                    <input
                      className="form-check-input ms-0 theme-control-toggle-input"
                      id="themeControlToggle"
                      type="checkbox"
                      data-theme-control="theme"
                      defaultValue="dark"
                    />
                    <label
                      className="mb-0 theme-control-toggle-label theme-control-toggle-light"
                      htmlFor="themeControlToggle"
                      data-bs-toggle="tooltip"
                      data-bs-placement="left"
                      title="Switch to light theme"
                    >
                      <span className="fas fa-sun fs-0" />
                    </label>
                    <label
                      className="mb-0 theme-control-toggle-label theme-control-toggle-dark"
                      htmlFor="themeControlToggle"
                      data-bs-toggle="tooltip"
                      data-bs-placement="left"
                      title="Switch to dark theme"
                    >
                      <span className="fas fa-moon fs-0" />
                    </label>
                  </div>
                </li>
                <li className="nav-item">
                  <a
                    className="nav-link px-0 notification-indicator notification-indicator-warning notification-indicator-fill fa-icon-wait"
                    href="app/e-commerce/shopping-cart.html"
                  >
                    <span
                      className="fas fa-shopping-cart"
                      data-fa-transform="shrink-7"
                      style={{ fontSize: 33 }}
                    />
                    <span className="notification-indicator-number">1</span>
                  </a>
                </li>
                <li className="nav-item dropdown">
                  <a
                    className="nav-link notification-indicator notification-indicator-primary px-0 fa-icon-wait"
                    id="navbarDropdownNotification"
                    href="#"
                    role="button"
                    data-bs-toggle="dropdown"
                    aria-haspopup="true"
                    aria-expanded="false"
                  >
                    <span
                      className="fas fa-bell"
                      data-fa-transform="shrink-6"
                      style={{ fontSize: 33 }}
                    />
                  </a>
                  <div
                    className="dropdown-menu dropdown-menu-end dropdown-menu-card dropdown-menu-notification"
                    aria-labelledby="navbarDropdownNotification"
                  >
                    <div className="card card-notification shadow-none">
                      <div className="card-header">
                        <div className="row justify-content-between align-items-center">
                          <div className="col-auto">
                            <h6 className="card-header-title mb-0">
                              Notifications
                            </h6>
                          </div>
                          <div className="col-auto ps-0 ps-sm-3">
                            <a className="card-link fw-normal" href="#">
                              Mark all as read
                            </a>
                          </div>
                        </div>
                      </div>
                      <div
                        className="scrollbar-overlay"
                        style={{ maxHeight: "19rem" }}
                      >
                        <div className="list-group list-group-flush fw-normal fs--1">
                          <div className="list-group-title border-bottom">
                            NEW
                          </div>
                          <div className="list-group-item">
                            <a
                              className="notification notification-flush notification-unread"
                              href="#!"
                            >
                              <div className="notification-avatar">
                                <div className="avatar avatar-2xl me-3">
                                  <img
                                    className="rounded-circle"
                                    src="/img/team/1-thumb.png"
                                    alt=""
                                  />
                                </div>
                              </div>
                              <div className="notification-body">
                                <p className="mb-1">
                                  <strong>Emma Watson</strong> replied to your
                                  comment : &quot;Hello world 😍
                                </p>
                                <span className="notification-time">
                                  <span
                                    className="me-2"
                                    role="img"
                                    aria-label="Emoji"
                                  >
                                    💬
                                  </span>
                                  Just now
                                </span>
                              </div>
                            </a>
                          </div>
                          <div className="list-group-item">
                            <a
                              className="notification notification-flush notification-unread"
                              href="#!"
                            >
                              <div className="notification-avatar">
                                <div className="avatar avatar-2xl me-3">
                                  <div className="avatar-name rounded-circle">
                                    <span>AB</span>
                                  </div>
                                </div>
                              </div>
                              <div className="notification-body">
                                <p className="mb-1">
                                  <strong>Albert Brooks</strong> reacted to{" "}
                                  <strong>Mia Khalifa&apos;s</strong> status
                                </p>
                                <span className="notification-time">
                                  <span className="me-2 fab fa-gratipay text-danger" />
                                  9hr
                                </span>
                              </div>
                            </a>
                          </div>
                          <div className="list-group-title border-bottom">
                            EARLIER
                          </div>
                          <div className="list-group-item">
                            <a
                              className="notification notification-flush"
                              href="#!"
                            >
                              <div className="notification-avatar">
                                <div className="avatar avatar-2xl me-3">
                                  <img
                                    className="rounded-circle"
                                    src="/img/icons/weather-sm.jpg"
                                    alt=""
                                  />
                                </div>
                              </div>
                              <div className="notification-body">
                                <p className="mb-1">
                                  The forecast today shows a low of 20℃ in
                                  California. See today&apos;s weather.
                                </p>
                                <span className="notification-time">
                                  <span
                                    className="me-2"
                                    role="img"
                                    aria-label="Emoji"
                                  >
                                    🌤️
                                  </span>
                                  1d
                                </span>
                              </div>
                            </a>
                          </div>
                          <div className="list-group-item">
                            <a
                              className="border-bottom-0 notification-unread  notification notification-flush"
                              href="#!"
                            >
                              <div className="notification-avatar">
                                <div className="avatar avatar-xl me-3">
                                  <img
                                    className="rounded-circle"
                                    src="/img/logos/oxford.png"
                                    alt=""
                                  />
                                </div>
                              </div>
                              <div className="notification-body">
                                <p className="mb-1">
                                  <strong>University of Oxford</strong> created
                                  an event : &quot;Causal Inference Hilary 2019
                                </p>
                                <span className="notification-time">
                                  <span
                                    className="me-2"
                                    role="img"
                                    aria-label="Emoji"
                                  >
                                    ✌️
                                  </span>
                                  1w
                                </span>
                              </div>
                            </a>
                          </div>
                          <div className="list-group-item">
                            <a
                              className="border-bottom-0 notification notification-flush"
                              href="#!"
                            >
                              <div className="notification-avatar">
                                <div className="avatar avatar-xl me-3">
                                  <img
                                    className="rounded-circle"
                                    src="/img/team/10.jpg"
                                    alt=""
                                  />
                                </div>
                              </div>
                              <div className="notification-body">
                                <p className="mb-1">
                                  <strong>James Cameron</strong> invited to join
                                  the group: United Nations International
                                  Children&apos;s Fund
                                </p>
                                <span className="notification-time">
                                  <span
                                    className="me-2"
                                    role="img"
                                    aria-label="Emoji"
                                  >
                                    🙋‍
                                  </span>
                                  2d
                                </span>
                              </div>
                            </a>
                          </div>
                        </div>
                      </div>
                      <div className="card-footer text-center border-top">
                        <a
                          className="card-link d-block"
                          href="app/social/notifications.html"
                        >
                          View all
                        </a>
                      </div>
                    </div>
                  </div>
                </li>
                <li className="nav-item dropdown">
                  <a
                    className="nav-link pe-0"
                    id="navbarDropdownUser"
                    href="#"
                    role="button"
                    data-bs-toggle="dropdown"
                    aria-haspopup="true"
                    aria-expanded="false"
                  >
                    <div className="avatar avatar-xl">
                      <img
                        className="rounded-circle"
                        src="img/bankks.png"
                        alt="Team"
                      />
                    </div>
                  </a>
                  <div
                    className="dropdown-menu dropdown-menu-end py-0"
                    aria-labelledby="navbarDropdownUser"
                  >
                    <div className="bg-white dark__bg-1000 rounded-2 py-2">
                      <a
                        className="dropdown-item fw-bold text-warning"
                        href="#!"
                      >
                        <span>Change Admin Password</span>
                      </a>
                      <div className="dropdown-divider" />
                      <a className="dropdown-item" href="#!">
                        Set status
                      </a>
                      <a
                        className="dropdown-item"
                        href="pages/user/profile.html"
                      >
                        Profile &amp; account
                      </a>
                      <a className="dropdown-item" href="#!">
                        Feedback
                      </a>
                      <div className="dropdown-divider" />
                      <a
                        className="dropdown-item"
                        href="pages/user/settings.html"
                      >
                        Settings
                      </a>
                      <Link
                        className="dropdown-item"
                        onClick={handleLogout}
                        to="/logout"
                      >
                        Logout
                      </Link>
                    </div>
                  </div>
                </li>
              </ul>
            </nav>
            <div>
              <div className="row g-3 mb-3">
                <div className="col-md-6 col-xxl-3">
                  <div className="card h-md-100 ecommerce-card-min-width">
                    <div className="card-header pb-0">
                      <h6 className="mb-0 mt-2 d-flex align-items-center">
                        Weekly Sales
                        <span
                          className="ms-1 text-400"
                          data-bs-toggle="tooltip"
                          data-bs-placement="top"
                          title="Calculated according to last week's sales"
                        >
                          <span
                            className="far fa-question-circle"
                            data-fa-transform="shrink-1"
                          />
                        </span>
                      </h6>
                    </div>
                    <div className="card-body d-flex flex-column justify-content-end">
                      <div className="row">
                        <div className="col">
                          <h2 className="font-sans-serif lh-1 mb-1 fs-4">
                            $47K
                          </h2>
                          <span className="badge badge-soft-success rounded-pill fs--2">
                            +3.5%
                          </span>
                        </div>
                        <div className="col-auto ps-0">
                          <div className="echart-bar-weekly-sales h-100" />
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="col-md-6 col-xxl-3">
                  <div className="card h-md-100">
                    <div className="card-header pb-0">
                      <h6 className="mb-0 mt-2">Total Order</h6>
                    </div>
                    <div className="card-body d-flex flex-column justify-content-end">
                      <div className="row justify-content-between">
                        <div className="col-auto align-self-end">
                          <div className="fs-4 fw-normal font-sans-serif text-700 lh-1 mb-1">
                            58.4K
                          </div>
                          <span className="badge rounded-pill fs--2 bg-200 text-primary">
                            <span className="fas fa-caret-up me-1" />
                            13.6%
                          </span>
                        </div>
                        <div className="col-auto ps-0 mt-n4">
                          <div
                            className="echart-default-total-order"
                            data-echarts='{"tooltip":{"trigger":"axis","formatter":"{b0} : {c0}"},"xAxis":{"data":["Week 4","Week 5","week 6","week 7"]},"series":[{"type":"line","data":[20,40,100,120],"smooth":true,"lineStyle":{"width":3}}],"grid":{"bottom":"2%","top":"2%","right":"10px","left":"10px"}}'
                            data-echart-responsive="true"
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="col-md-6 col-xxl-3">
                  <div className="card h-md-100">
                    <div className="card-body">
                      <div className="row h-100 justify-content-between g-0">
                        <div className="col-5 col-sm-6 col-xxl pe-2">
                          <h6 className="mt-1">Market Share</h6>
                          <div className="fs--2 mt-3">
                            <div className="d-flex flex-between-center mb-1">
                              <div className="d-flex align-items-center">
                                <span className="dot bg-primary" />
                                <span className="fw-semi-bold">samsung</span>
                              </div>
                              <div className="d-xxl-none">33%</div>
                            </div>
                            <div className="d-flex flex-between-center mb-1">
                              <div className="d-flex align-items-center">
                                <span className="dot bg-info" />
                                <span className="fw-semi-bold">Huawei</span>
                              </div>
                              <div className="d-xxl-none">29%</div>
                            </div>
                            <div className="d-flex flex-between-center mb-1">
                              <div className="d-flex align-items-center">
                                <span className="dot bg-300" />
                                <span className="fw-semi-bold">Huawei</span>
                              </div>
                              <div className="d-xxl-none">20%</div>
                            </div>
                          </div>
                        </div>
                        <div className="col-auto position-relative">
                          <div className="echart-market-share" />
                          <div className="position-absolute top-50 start-50 translate-middle text-dark fs-2">
                            26M
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="col-md-6 col-xxl-3">
                  <div className="card h-md-100">
                    <div className="card-header d-flex flex-between-center pb-0">
                      <h6 className="mb-0">Weather</h6>
                      <div className="dropdown font-sans-serif btn-reveal-trigger">
                        <button
                          className="btn btn-link text-600 btn-sm dropdown-toggle dropdown-caret-none btn-reveal"
                          type="button"
                          id="dropdown-weather-update"
                          data-bs-toggle="dropdown"
                          data-boundary="viewport"
                          aria-haspopup="true"
                          aria-expanded="false"
                        >
                          <span className="fas fa-ellipsis-h fs--2" />
                        </button>
                        <div
                          className="dropdown-menu dropdown-menu-end border py-2"
                          aria-labelledby="dropdown-weather-update"
                        >
                          <a className="dropdown-item" href="#!">
                            View
                          </a>
                          <a className="dropdown-item" href="#!">
                            Export
                          </a>
                          <div className="dropdown-divider" />
                          <a className="dropdown-item text-danger" href="#!">
                            Remove
                          </a>
                        </div>
                      </div>
                    </div>
                    <div className="card-body pt-2">
                      <div className="row g-0 h-100 align-items-center">
                        <div className="col">
                          <div className="d-flex align-items-center">
                            <img
                              className="me-3"
                              src="/img/icons/weather-icon.png"
                              alt=""
                              height={60}
                            />
                            <div>
                              <h6 className="mb-2">New York City</h6>
                              <div className="fs--2 fw-semi-bold">
                                <div className="text-warning">Sunny</div>
                                Precipitation: 50%
                              </div>
                            </div>
                          </div>
                        </div>
                        <div className="col-auto text-center ps-2">
                          <div className="fs-4 fw-normal font-sans-serif text-primary mb-1 lh-1">
                            31°
                          </div>
                          <div className="fs--1 text-800">32° / 25°</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div className="row g-0">
                <div className="col-lg-6 pe-lg-2 mb-3">
                  <div className="card h-lg-100 overflow-hidden">
                    <div className="card-header bg-light">
                      <div className="row align-items-center">
                        <div className="col">
                          <h6 className="mb-0">Running Projects</h6>
                        </div>
                        <div className="col-auto text-center pe-card">
                          <select className="form-select form-select-sm">
                            <option>Working Time</option>
                            <option>Estimated Time</option>
                            <option>Billable Time</option>
                          </select>
                        </div>
                      </div>
                    </div>
                    <div className="card-body p-0">
                      <div className="row g-0 align-items-center py-2 position-relative border-bottom border-200">
                        <div className="col ps-card py-1 position-static">
                          <div className="d-flex align-items-center">
                            <div className="avatar avatar-xl me-3">
                              <div className="avatar-name rounded-circle bg-soft-primary text-dark">
                                <span className="fs-0 text-primary">F</span>
                              </div>
                            </div>
                            <div className="flex-1">
                              <h6 className="mb-0 d-flex align-items-center">
                                <a
                                  className="text-800 stretched-link"
                                  href="#!"
                                >
                                  Dashboard
                                </a>
                                <span className="badge rounded-pill ms-2 bg-200 text-primary">
                                  38%
                                </span>
                              </h6>
                            </div>
                          </div>
                        </div>
                        <div className="col py-1">
                          <div className="row flex-end-center g-0">
                            <div className="col-auto pe-2">
                              <div className="fs--1 fw-semi-bold">12:50:00</div>
                            </div>
                            <div className="col-5 pe-card ps-2">
                              <div
                                className="progress bg-200 me-2"
                                style={{ height: 5 }}
                              >
                                <div
                                  className="progress-bar rounded-pill"
                                  role="progressbar"
                                  style={{ width: "38%" }}
                                  aria-valuenow={38}
                                  aria-valuemin={0}
                                  aria-valuemax={100}
                                />
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div className="row g-0 align-items-center py-2 position-relative border-bottom border-200">
                        <div className="col ps-card py-1 position-static">
                          <div className="d-flex align-items-center">
                            <div className="avatar avatar-xl me-3">
                              <div className="avatar-name rounded-circle bg-soft-success text-dark">
                                <span className="fs-0 text-success">R</span>
                              </div>
                            </div>
                            <div className="flex-1">
                              <h6 className="mb-0 d-flex align-items-center">
                                <a
                                  className="text-800 stretched-link"
                                  href="#!"
                                >
                                  Reign
                                </a>
                                <span className="badge rounded-pill ms-2 bg-200 text-primary">
                                  79%
                                </span>
                              </h6>
                            </div>
                          </div>
                        </div>
                        <div className="col py-1">
                          <div className="row flex-end-center g-0">
                            <div className="col-auto pe-2">
                              <div className="fs--1 fw-semi-bold">25:20:00</div>
                            </div>
                            <div className="col-5 pe-card ps-2">
                              <div
                                className="progress bg-200 me-2"
                                style={{ height: 5 }}
                              >
                                <div
                                  className="progress-bar rounded-pill"
                                  role="progressbar"
                                  style={{ width: "79%" }}
                                  aria-valuenow={79}
                                  aria-valuemin={0}
                                  aria-valuemax={100}
                                />
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div className="row g-0 align-items-center py-2 position-relative border-bottom border-200">
                        <div className="col ps-card py-1 position-static">
                          <div className="d-flex align-items-center">
                            <div className="avatar avatar-xl me-3">
                              <div className="avatar-name rounded-circle bg-soft-info text-dark">
                                <span className="fs-0 text-info">B</span>
                              </div>
                            </div>
                            <div className="flex-1">
                              <h6 className="mb-0 d-flex align-items-center">
                                <a
                                  className="text-800 stretched-link"
                                  href="#!"
                                >
                                  Boots4
                                </a>
                                <span className="badge rounded-pill ms-2 bg-200 text-primary">
                                  90%
                                </span>
                              </h6>
                            </div>
                          </div>
                        </div>
                        <div className="col py-1">
                          <div className="row flex-end-center g-0">
                            <div className="col-auto pe-2">
                              <div className="fs--1 fw-semi-bold">58:20:00</div>
                            </div>
                            <div className="col-5 pe-card ps-2">
                              <div
                                className="progress bg-200 me-2"
                                style={{ height: 5 }}
                              >
                                <div
                                  className="progress-bar rounded-pill"
                                  role="progressbar"
                                  style={{ width: "90%" }}
                                  aria-valuenow={90}
                                  aria-valuemin={0}
                                  aria-valuemax={100}
                                />
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div className="row g-0 align-items-center py-2 position-relative border-bottom border-200">
                        <div className="col ps-card py-1 position-static">
                          <div className="d-flex align-items-center">
                            <div className="avatar avatar-xl me-3">
                              <div className="avatar-name rounded-circle bg-soft-warning text-dark">
                                <span className="fs-0 text-warning">R</span>
                              </div>
                            </div>
                            <div className="flex-1">
                              <h6 className="mb-0 d-flex align-items-center">
                                <a
                                  className="text-800 stretched-link"
                                  href="#!"
                                >
                                  Raven
                                </a>
                                <span className="badge rounded-pill ms-2 bg-200 text-primary">
                                  40%
                                </span>
                              </h6>
                            </div>
                          </div>
                        </div>
                        <div className="col py-1">
                          <div className="row flex-end-center g-0">
                            <div className="col-auto pe-2">
                              <div className="fs--1 fw-semi-bold">21:20:00</div>
                            </div>
                            <div className="col-5 pe-card ps-2">
                              <div
                                className="progress bg-200 me-2"
                                style={{ height: 5 }}
                              >
                                <div
                                  className="progress-bar rounded-pill"
                                  role="progressbar"
                                  style={{ width: "40%" }}
                                  aria-valuenow={40}
                                  aria-valuemin={0}
                                  aria-valuemax={100}
                                />
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div className="row g-0 align-items-center py-2 position-relative">
                        <div className="col ps-card py-1 position-static">
                          <div className="d-flex align-items-center">
                            <div className="avatar avatar-xl me-3">
                              <div className="avatar-name rounded-circle bg-soft-danger text-dark">
                                <span className="fs-0 text-danger">S</span>
                              </div>
                            </div>
                            <div className="flex-1">
                              <h6 className="mb-0 d-flex align-items-center">
                                <a
                                  className="text-800 stretched-link"
                                  href="#!"
                                >
                                  Slick
                                </a>
                                <span className="badge rounded-pill ms-2 bg-200 text-primary">
                                  70%
                                </span>
                              </h6>
                            </div>
                          </div>
                        </div>
                        <div className="col py-1">
                          <div className="row flex-end-center g-0">
                            <div className="col-auto pe-2">
                              <div className="fs--1 fw-semi-bold">31:20:00</div>
                            </div>
                            <div className="col-5 pe-card ps-2">
                              <div
                                className="progress bg-200 me-2"
                                style={{ height: 5 }}
                              >
                                <div
                                  className="progress-bar rounded-pill"
                                  role="progressbar"
                                  style={{ width: "70%" }}
                                  aria-valuenow={70}
                                  aria-valuemin={0}
                                  aria-valuemax={100}
                                />
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                    <div className="card-footer bg-light p-0">
                      <a
                        className="btn btn-sm btn-link d-block w-100 py-2"
                        href="#!"
                      >
                        Show all projects
                        <span className="fas fa-chevron-right ms-1 fs--2" />
                      </a>
                    </div>
                  </div>
                </div>
                <div className="col-lg-6 ps-lg-2 mb-3">
                  <div className="card h-lg-100">
                    <div className="card-header">
                      <div className="row flex-between-center">
                        <div className="col-auto">
                          <h6 className="mb-0">Total Sales</h6>
                        </div>
                        <div className="col-auto d-flex">
                          <select className="form-select form-select-sm select-month me-2">
                            <option value={0}>January</option>
                            <option value={1}>February</option>
                            <option value={2}>March</option>
                            <option value={3}>April</option>
                            <option value={4}>May</option>
                            <option value={5}>Jun</option>
                            <option value={6}>July</option>
                            <option value={7}>August</option>
                            <option value={8}>September</option>
                            <option value={9}>October</option>
                            <option value={10}>November</option>
                            <option value={11}>December</option>
                          </select>
                          <div className="dropdown font-sans-serif btn-reveal-trigger">
                            <button
                              className="btn btn-link text-600 btn-sm dropdown-toggle dropdown-caret-none btn-reveal"
                              type="button"
                              id="dropdown-total-sales"
                              data-bs-toggle="dropdown"
                              data-boundary="viewport"
                              aria-haspopup="true"
                              aria-expanded="false"
                            >
                              <span className="fas fa-ellipsis-h fs--2" />
                            </button>
                            <div
                              className="dropdown-menu dropdown-menu-end border py-2"
                              aria-labelledby="dropdown-total-sales"
                            >
                              <a className="dropdown-item" href="#!">
                                View
                              </a>
                              <a className="dropdown-item" href="#!">
                                Export
                              </a>
                              <div className="dropdown-divider" />
                              <a
                                className="dropdown-item text-danger"
                                href="#!"
                              >
                                Remove
                              </a>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                    <div className="card-body h-100 pe-0">
                      {/* Find the JS file for the following chart at: src\js\charts\echarts\total-sales.js*/}
                      {/* If you are not using gulp based workflow, you can find the transpiled code at: public\assets\js\theme.js*/}
                      <div
                        className="echart-line-total-sales h-100"
                        data-echart-responsive="true"
                      />
                    </div>
                  </div>
                </div>
              </div>
              <div className="row g-0">
                <div className="col-lg-6 col-xl-7 col-xxl-8 mb-3 pe-lg-2 mb-3">
                  <div className="card h-lg-100">
                    <div className="card-body d-flex align-items-center">
                      <div className="w-100">
                        <h6 className="mb-3 text-800">
                          Using Storage{" "}
                          <strong className="text-dark">1775.06 MB </strong>of 2
                          GB
                        </h6>
                        <div
                          className="progress mb-3 rounded-3"
                          style={{ height: 10 }}
                        >
                          <div
                            className="progress-bar bg-progress-gradient border-end border-white border-2"
                            role="progressbar"
                            style={{ width: "43.72%" }}
                            aria-valuenow="43.72"
                            aria-valuemin={0}
                            aria-valuemax={100}
                          />
                          <div
                            className="progress-bar bg-info border-end border-white border-2"
                            role="progressbar"
                            style={{ width: "18.76%" }}
                            aria-valuenow="18.76"
                            aria-valuemin={0}
                            aria-valuemax={100}
                          />
                          <div
                            className="progress-bar bg-success border-end border-white border-2"
                            role="progressbar"
                            style={{ width: "9.38%" }}
                            aria-valuenow="9.38"
                            aria-valuemin={0}
                            aria-valuemax={100}
                          />
                          <div
                            className="progress-bar bg-200"
                            role="progressbar"
                            style={{ width: "28.14%" }}
                            aria-valuenow="28.14"
                            aria-valuemin={0}
                            aria-valuemax={100}
                          />
                        </div>
                        <div className="row fs--1 fw-semi-bold text-500 g-0">
                          <div className="col-auto d-flex align-items-center pe-3">
                            <span className="dot bg-primary" />
                            <span>Regular</span>
                            <span className="d-none d-md-inline-block d-lg-none d-xxl-inline-block">
                              (895MB)
                            </span>
                          </div>
                          <div className="col-auto d-flex align-items-center pe-3">
                            <span className="dot bg-info" />
                            <span>System</span>
                            <span className="d-none d-md-inline-block d-lg-none d-xxl-inline-block">
                              (379MB)
                            </span>
                          </div>
                          <div className="col-auto d-flex align-items-center pe-3">
                            <span className="dot bg-success" />
                            <span>Shared</span>
                            <span className="d-none d-md-inline-block d-lg-none d-xxl-inline-block">
                              (192MB)
                            </span>
                          </div>
                          <div className="col-auto d-flex align-items-center">
                            <span className="dot bg-200" />
                            <span>Free</span>
                            <span className="d-none d-md-inline-block d-lg-none d-xxl-inline-block">
                              (576MB)
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="col-lg-6 col-xl-5 col-xxl-4 mb-3 ps-lg-2">
                  <div className="card h-lg-100">
                    <div
                      className="bg-holder bg-card"
                      style={{
                        backgroundImage:
                          "url(img/icons/spot-illustrations/corner-1.png)",
                      }}
                    ></div>
                    {/*/.bg-holder*/}
                    <div className="card-body position-relative">
                      <h5 className="text-warning">
                        Running out of your space?
                      </h5>
                      <p className="fs--1 mb-0">
                        Your storage will be running out soon. Get more space
                        and powerful productivity features.
                      </p>
                      <a
                        className="btn btn-link fs--1 text-warning mt-lg-3 ps-0"
                        href="#!"
                      >
                        Upgrade storage
                        <span
                          className="fas fa-chevron-right ms-1"
                          data-fa-transform="shrink-4 down-1"
                        />
                      </a>
                    </div>
                  </div>
                </div>
              </div>
              <div className="row g-0">
                <div className="col-lg-7 col-xl-8 pe-lg-2 mb-3">
                  <div className="card h-lg-100 overflow-hidden">
                    <div className="card-body p-0">
                      <div className="table-responsive scrollbar">
                        <table className="table table-dashboard mb-0 table-borderless fs--1 border-200">
                          <thead className="bg-light">
                            <tr className="text-900">
                              <th>Best Selling Products</th>
                              <th className="text-end">Revenue ($3333)</th>
                              <th
                                className="pe-card text-end"
                                style={{ width: "8rem" }}
                              >
                                Revenue (%)
                              </th>
                            </tr>
                          </thead>
                          <tbody>
                            <tr className="border-bottom border-200">
                              <td>
                                <div className="d-flex align-items-center position-relative">
                                  <img
                                    className="rounded-1 border border-200"
                                    src="/img/products/12.png"
                                    width={60}
                                    alt="Products"
                                  />
                                  <div className="flex-1 ms-3">
                                    <h6 className="mb-1 fw-semi-bold">
                                      <a
                                        className="text-dark stretched-link"
                                        href="#!"
                                      >
                                        Raven Pro
                                      </a>
                                    </h6>
                                    <p className="fw-semi-bold mb-0 text-500">
                                      Landing
                                    </p>
                                  </div>
                                </div>
                              </td>
                              <td className="align-middle text-end fw-semi-bold">
                                $1311
                              </td>
                              <td className="align-middle pe-card">
                                <div className="d-flex align-items-center">
                                  <div
                                    className="progress me-3 rounded-3 bg-200"
                                    style={{ height: 5, width: 80 }}
                                  >
                                    <div
                                      className="progress-bar rounded-pill"
                                      role="progressbar"
                                      style={{ width: "39%" }}
                                      aria-valuenow={39}
                                      aria-valuemin={0}
                                      aria-valuemax={100}
                                    />
                                  </div>
                                  <div className="fw-semi-bold ms-2">39%</div>
                                </div>
                              </td>
                            </tr>
                            <tr className="border-bottom border-200">
                              <td>
                                <div className="d-flex align-items-center position-relative">
                                  <img
                                    className="rounded-1 border border-200"
                                    src="/img/products/10.png"
                                    width={60}
                                    alt=""
                                  />
                                  <div className="flex-1 ms-3">
                                    <h6 className="mb-1 fw-semi-bold">
                                      <a
                                        className="text-dark stretched-link"
                                        href="#!"
                                      >
                                        Boots4
                                      </a>
                                    </h6>
                                    <p className="fw-semi-bold mb-0 text-500">
                                      Portfolio
                                    </p>
                                  </div>
                                </div>
                              </td>
                              <td className="align-middle text-end fw-semi-bold">
                                $860
                              </td>
                              <td className="align-middle pe-card">
                                <div className="d-flex align-items-center">
                                  <div
                                    className="progress me-3 rounded-3 bg-200"
                                    style={{ height: 5, width: 80 }}
                                  >
                                    <div
                                      className="progress-bar rounded-pill"
                                      role="progressbar"
                                      style={{ width: "26%" }}
                                      aria-valuenow={26}
                                      aria-valuemin={0}
                                      aria-valuemax={100}
                                    />
                                  </div>
                                  <div className="fw-semi-bold ms-2">26%</div>
                                </div>
                              </td>
                            </tr>
                            <tr className="border-bottom border-200">
                              <td>
                                <div className="d-flex align-items-center position-relative">
                                  <img
                                    className="rounded-1 border border-200"
                                    src="/img/products/11.png"
                                    width={60}
                                    alt=""
                                  />
                                  <div className="flex-1 ms-3">
                                    <h6 className="mb-1 fw-semi-bold">
                                      <a
                                        className="text-dark stretched-link"
                                        href="#!"
                                      >
                                        Falcon
                                      </a>
                                    </h6>
                                    <p className="fw-semi-bold mb-0 text-500">
                                      Admin
                                    </p>
                                  </div>
                                </div>
                              </td>
                              <td className="align-middle text-end fw-semi-bold">
                                $539
                              </td>
                              <td className="align-middle pe-card">
                                <div className="d-flex align-items-center">
                                  <div
                                    className="progress me-3 rounded-3 bg-200"
                                    style={{ height: 5, width: 80 }}
                                  >
                                    <div
                                      className="progress-bar rounded-pill"
                                      role="progressbar"
                                      style={{ width: "16%" }}
                                      aria-valuenow={16}
                                      aria-valuemin={0}
                                      aria-valuemax={100}
                                    />
                                  </div>
                                  <div className="fw-semi-bold ms-2">16%</div>
                                </div>
                              </td>
                            </tr>
                            <tr className="border-bottom border-200">
                              <td>
                                <div className="d-flex align-items-center position-relative">
                                  <img
                                    className="rounded-1 border border-200"
                                    src="/img/products/14.png"
                                    width={60}
                                    alt=""
                                  />
                                  <div className="flex-1 ms-3">
                                    <h6 className="mb-1 fw-semi-bold">
                                      <a
                                        className="text-dark stretched-link"
                                        href="#!"
                                      >
                                        Slick
                                      </a>
                                    </h6>
                                    <p className="fw-semi-bold mb-0 text-500">
                                      Builder
                                    </p>
                                  </div>
                                </div>
                              </td>
                              <td className="align-middle text-end fw-semi-bold">
                                $343
                              </td>
                              <td className="align-middle pe-card">
                                <div className="d-flex align-items-center">
                                  <div
                                    className="progress me-3 rounded-3 bg-200"
                                    style={{ height: 5, width: 80 }}
                                  >
                                    <div
                                      className="progress-bar rounded-pill"
                                      role="progressbar"
                                      style={{ width: "10%" }}
                                      aria-valuenow={10}
                                      aria-valuemin={0}
                                      aria-valuemax={100}
                                    />
                                  </div>
                                  <div className="fw-semi-bold ms-2">10%</div>
                                </div>
                              </td>
                            </tr>
                            <tr>
                              <td>
                                <div className="d-flex align-items-center position-relative">
                                  <img
                                    className="rounded-1 border border-200"
                                    src="/img/products/13.png"
                                    width={60}
                                    alt=""
                                  />
                                  <div className="flex-1 ms-3">
                                    <h6 className="mb-1 fw-semi-bold">
                                      <a
                                        className="text-dark stretched-link"
                                        href="#!"
                                      >
                                        Reign Pro
                                      </a>
                                    </h6>
                                    <p className="fw-semi-bold mb-0 text-500">
                                      Agency
                                    </p>
                                  </div>
                                </div>
                              </td>
                              <td className="align-middle text-end fw-semi-bold">
                                $280
                              </td>
                              <td className="align-middle pe-card">
                                <div className="d-flex align-items-center">
                                  <div
                                    className="progress me-3 rounded-3 bg-200"
                                    style={{ height: 5, width: 80 }}
                                  >
                                    <div
                                      className="progress-bar rounded-pill"
                                      role="progressbar"
                                      style={{ width: "8%" }}
                                      aria-valuenow={8}
                                      aria-valuemin={0}
                                      aria-valuemax={100}
                                    />
                                  </div>
                                  <div className="fw-semi-bold ms-2">8%</div>
                                </div>
                              </td>
                            </tr>
                          </tbody>
                        </table>
                      </div>
                    </div>
                    <div className="card-footer bg-light py-2">
                      <div className="row flex-between-center">
                        <div className="col-auto">
                          <select className="form-select form-select-sm">
                            <option>Last 7 days</option>
                            <option>Last Month</option>
                            <option>Last Year</option>
                          </select>
                        </div>
                        <div className="col-auto">
                          <a
                            className="btn btn-sm btn-falcon-default"
                            href="#!"
                          >
                            View All
                          </a>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="col-lg-5 col-xl-4 ps-lg-2 mb-3">
                  <div className="card">
                    <div className="card-header d-flex flex-between-center bg-light py-2">
                      <h6 className="mb-0">Shared Files</h6>
                      <a className="py-1 fs--1 font-sans-serif" href="#!">
                        View All
                      </a>
                    </div>
                    <div className="card-body pb-0">
                      <div className="d-flex mb-3 hover-actions-trigger align-items-center">
                        <div className="file-thumbnail">
                          <img
                            className="border h-100 w-100 fit-cover rounded-2"
                            src="/img/products/5-thumb.png"
                            alt=""
                          />
                        </div>
                        <div className="ms-3 flex-shrink-1 flex-grow-1">
                          <h6 className="mb-1">
                            <a
                              className="stretched-link text-900 fw-semi-bold"
                              href="#!"
                            >
                              apple-smart-watch.png
                            </a>
                          </h6>
                          <div className="fs--1">
                            <span className="fw-semi-bold">Antony</span>
                            <span className="fw-medium text-600 ms-2">
                              Just Now
                            </span>
                          </div>
                          <div className="hover-actions end-0 top-50 translate-middle-y">
                            <a
                              className="btn btn-light border-300 btn-sm me-1 text-600"
                              data-bs-toggle="tooltip"
                              data-bs-placement="top"
                              title="Download"
                              href="/img/icons/cloud-download.svg"
                              download="download"
                            >
                              <img
                                src="/img/icons/cloud-download.svg"
                                alt=""
                                width={15}
                              />
                            </a>
                            <button
                              className="btn btn-light border-300 btn-sm me-1 text-600 shadow-none"
                              type="button"
                              data-bs-toggle="tooltip"
                              data-bs-placement="top"
                              title="Edit"
                            >
                              <img
                                src="/img/icons/edit-alt.svg"
                                alt=""
                                width={15}
                              />
                            </button>
                          </div>
                        </div>
                      </div>
                      <hr className="bg-200" />
                      <div className="d-flex mb-3 hover-actions-trigger align-items-center">
                        <div className="file-thumbnail">
                          <img
                            className="border h-100 w-100 fit-cover rounded-2"
                            src="/img/products/3-thumb.png"
                            alt=""
                          />
                        </div>
                        <div className="ms-3 flex-shrink-1 flex-grow-1">
                          <h6 className="mb-1">
                            <a
                              className="stretched-link text-900 fw-semi-bold"
                              href="#!"
                            >
                              iphone.jpg
                            </a>
                          </h6>
                          <div className="fs--1">
                            <span className="fw-semi-bold">Antony</span>
                            <span className="fw-medium text-600 ms-2">
                              Yesterday at 1:30 PM
                            </span>
                          </div>
                          <div className="hover-actions end-0 top-50 translate-middle-y">
                            <a
                              className="btn btn-light border-300 btn-sm me-1 text-600"
                              data-bs-toggle="tooltip"
                              data-bs-placement="top"
                              title="Download"
                              href="/img/icons/cloud-download.svg"
                              download="download"
                            >
                              <img
                                src="/img/icons/cloud-download.svg"
                                alt=""
                                width={15}
                              />
                            </a>
                            <button
                              className="btn btn-light border-300 btn-sm me-1 text-600 shadow-none"
                              type="button"
                              data-bs-toggle="tooltip"
                              data-bs-placement="top"
                              title="Edit"
                            >
                              <img
                                src="img/icons/edit-alt.svg"
                                alt=""
                                width={15}
                              />
                            </button>
                          </div>
                        </div>
                      </div>
                      <hr className="bg-200" />
                      <div className="d-flex mb-3 hover-actions-trigger align-items-center">
                        <div className="file-thumbnail">
                          <img
                            className="img-fluid"
                            src="img/icons/zip.png"
                            alt=""
                          />
                        </div>
                        <div className="ms-3 flex-shrink-1 flex-grow-1">
                          <h6 className="mb-1">
                            <a
                              className="stretched-link text-900 fw-semi-bold"
                              href="#!"
                            >
                              Falcon v1.8.2
                            </a>
                          </h6>
                          <div className="fs--1">
                            <span className="fw-semi-bold">Jane</span>
                            <span className="fw-medium text-600 ms-2">
                              27 Sep at 10:30 AM
                            </span>
                          </div>
                          <div className="hover-actions end-0 top-50 translate-middle-y">
                            <a
                              className="btn btn-light border-300 btn-sm me-1 text-600"
                              data-bs-toggle="tooltip"
                              data-bs-placement="top"
                              title="Download"
                              href="img/icons/cloud-download.svg"
                              download="download"
                            >
                              <img
                                src="img/icons/cloud-download.svg"
                                alt=""
                                width={15}
                              />
                            </a>
                            <button
                              className="btn btn-light border-300 btn-sm me-1 text-600 shadow-none"
                              type="button"
                              data-bs-toggle="tooltip"
                              data-bs-placement="top"
                              title="Edit"
                            >
                              <img
                                src="img/icons/edit-alt.svg"
                                alt=""
                                width={15}
                              />
                            </button>
                          </div>
                        </div>
                      </div>
                      <hr className="bg-200" />
                      <div className="d-flex mb-3 hover-actions-trigger align-items-center">
                        <div className="file-thumbnail">
                          <img
                            className="border h-100 w-100 fit-cover rounded-2"
                            src="/img/products/2-thumb.png"
                            alt=""
                          />
                        </div>
                        <div className="ms-3 flex-shrink-1 flex-grow-1">
                          <h6 className="mb-1">
                            <a
                              className="stretched-link text-900 fw-semi-bold"
                              href="#!"
                            >
                              iMac.jpg
                            </a>
                          </h6>
                          <div className="fs--1">
                            <span className="fw-semi-bold">Rowen</span>
                            <span className="fw-medium text-600 ms-2">
                              23 Sep at 6:10 PM
                            </span>
                          </div>
                          <div className="hover-actions end-0 top-50 translate-middle-y">
                            <a
                              className="btn btn-light border-300 btn-sm me-1 text-600"
                              data-bs-toggle="tooltip"
                              data-bs-placement="top"
                              title="Download"
                              href="img/icons/cloud-download.svg"
                              download="download"
                            >
                              <img
                                src="img/icons/cloud-download.svg"
                                alt=""
                                width={15}
                              />
                            </a>
                            <button
                              className="btn btn-light border-300 btn-sm me-1 text-600 shadow-none"
                              type="button"
                              data-bs-toggle="tooltip"
                              data-bs-placement="top"
                              title="Edit"
                            >
                              <img
                                src="img/icons/edit-alt.svg"
                                alt=""
                                width={15}
                              />
                            </button>
                          </div>
                        </div>
                      </div>
                      <hr className="bg-200" />
                      <div className="d-flex mb-3 hover-actions-trigger align-items-center">
                        <div className="file-thumbnail">
                          <img
                            className="img-fluid"
                            src="img/icons/docs.png"
                            alt=""
                          />
                        </div>
                        <div className="ms-3 flex-shrink-1 flex-grow-1">
                          <h6 className="mb-1">
                            <a
                              className="stretched-link text-900 fw-semi-bold"
                              href="#!"
                            >
                              functions.php
                            </a>
                          </h6>
                          <div className="fs--1">
                            <span className="fw-semi-bold">John</span>
                            <span className="fw-medium text-600 ms-2">
                              1 Oct at 4:30 PM
                            </span>
                          </div>
                          <div className="hover-actions end-0 top-50 translate-middle-y">
                            <a
                              className="btn btn-light border-300 btn-sm me-1 text-600"
                              data-bs-toggle="tooltip"
                              data-bs-placement="top"
                              title="Download"
                              href="img/icons/cloud-download.svg"
                              download="download"
                            >
                              <img
                                src="img/icons/cloud-download.svg"
                                alt=""
                                width={15}
                              />
                            </a>
                            <button
                              className="btn btn-light border-300 btn-sm me-1 text-600 shadow-none"
                              type="button"
                              data-bs-toggle="tooltip"
                              data-bs-placement="top"
                              title="Edit"
                            >
                              <img
                                src="img/icons/edit-alt.svg"
                                alt=""
                                width={15}
                              />
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div className="row g-0">
                <div className="col-sm-6 col-xxl-3 pe-sm-2 mb-3 mb-xxl-0">
                  <div className="card">
                    <div className="card-header d-flex flex-between-center bg-light py-2">
                      <h6 className="mb-0">Active Users</h6>
                      <div className="dropdown font-sans-serif btn-reveal-trigger">
                        <button
                          className="btn btn-link text-600 btn-sm dropdown-toggle dropdown-caret-none btn-reveal"
                          type="button"
                          id="dropdown-active-user"
                          data-bs-toggle="dropdown"
                          data-boundary="viewport"
                          aria-haspopup="true"
                          aria-expanded="false"
                        >
                          <span className="fas fa-ellipsis-h fs--2" />
                        </button>
                        <div
                          className="dropdown-menu dropdown-menu-end border py-2"
                          aria-labelledby="dropdown-active-user"
                        >
                          <a className="dropdown-item" href="#!">
                            View
                          </a>
                          <a className="dropdown-item" href="#!">
                            Export
                          </a>
                          <div className="dropdown-divider" />
                          <a className="dropdown-item text-danger" href="#!">
                            Remove
                          </a>
                        </div>
                      </div>
                    </div>
                    <div className="card-body py-2">
                      <div className="d-flex align-items-center position-relative mb-3">
                        <div className="avatar avatar-2xl status-online">
                          <img
                            className="rounded-circle"
                            src="img/team/1.jpg"
                            alt=""
                          />
                        </div>
                        <div className="flex-1 ms-3">
                          <h6 className="mb-0 fw-semi-bold">
                            <a
                              className="stretched-link text-900"
                              href="pages/user/profile.html"
                            >
                              Emma Watson
                            </a>
                          </h6>
                          <p className="text-500 fs--2 mb-0">Admin</p>
                        </div>
                      </div>
                      <div className="d-flex align-items-center position-relative mb-3">
                        <div className="avatar avatar-2xl status-online">
                          <img
                            className="rounded-circle"
                            src="img/team/2.jpg"
                            alt=""
                          />
                        </div>
                        <div className="flex-1 ms-3">
                          <h6 className="mb-0 fw-semi-bold">
                            <a
                              className="stretched-link text-900"
                              href="pages/user/profile.html"
                            >
                              Antony Hopkins
                            </a>
                          </h6>
                          <p className="text-500 fs--2 mb-0">Moderator</p>
                        </div>
                      </div>
                      <div className="d-flex align-items-center position-relative mb-3">
                        <div className="avatar avatar-2xl status-away">
                          <img
                            className="rounded-circle"
                            src="img/team/3.jpg"
                            alt=""
                          />
                        </div>
                        <div className="flex-1 ms-3">
                          <h6 className="mb-0 fw-semi-bold">
                            <a
                              className="stretched-link text-900"
                              href="pages/user/profile.html"
                            >
                              Anna Karinina
                            </a>
                          </h6>
                          <p className="text-500 fs--2 mb-0">Editor</p>
                        </div>
                      </div>
                      <div className="d-flex align-items-center position-relative mb-3">
                        <div className="avatar avatar-2xl status-offline">
                          <img
                            className="rounded-circle"
                            src="img/team/4.jpg"
                            alt=""
                          />
                        </div>
                        <div className="flex-1 ms-3">
                          <h6 className="mb-0 fw-semi-bold">
                            <a
                              className="stretched-link text-900"
                              href="pages/user/profile.html"
                            >
                              John Lee
                            </a>
                          </h6>
                          <p className="text-500 fs--2 mb-0">Admin</p>
                        </div>
                      </div>
                      <div className="d-flex align-items-center position-relative false">
                        <div className="avatar avatar-2xl status-offline">
                          <img
                            className="rounded-circle"
                            src="img/team/5.jpg"
                            alt=""
                          />
                        </div>
                        <div className="flex-1 ms-3">
                          <h6 className="mb-0 fw-semi-bold">
                            <a
                              className="stretched-link text-900"
                              href="pages/user/profile.html"
                            >
                              Rowen Atkinson
                            </a>
                          </h6>
                          <p className="text-500 fs--2 mb-0">Editor</p>
                        </div>
                      </div>
                    </div>
                    <div className="card-footer bg-light p-0">
                      <a
                        className="btn btn-sm btn-link d-block w-100 py-2"
                        href="app/social/followers.html"
                      >
                        All active users
                        <span className="fas fa-chevron-right ms-1 fs--2" />
                      </a>
                    </div>
                  </div>
                </div>
                <div className="col-sm-6 col-xxl-3 ps-sm-2 order-xxl-1 mb-3 mb-xxl-0">
                  <div className="card h-100">
                    <div className="card-header bg-light d-flex flex-between-center py-2">
                      <h6 className="mb-0">Bandwidth Saved</h6>
                      <div className="dropdown font-sans-serif btn-reveal-trigger">
                        <button
                          className="btn btn-link text-600 btn-sm dropdown-toggle dropdown-caret-none btn-reveal"
                          type="button"
                          id="dropdown-bandwidth-saved"
                          data-bs-toggle="dropdown"
                          data-boundary="viewport"
                          aria-haspopup="true"
                          aria-expanded="false"
                        >
                          <span className="fas fa-ellipsis-h fs--2" />
                        </button>
                        <div
                          className="dropdown-menu dropdown-menu-end border py-2"
                          aria-labelledby="dropdown-bandwidth-saved"
                        >
                          <a className="dropdown-item" href="#!">
                            View
                          </a>
                          <a className="dropdown-item" href="#!">
                            Export
                          </a>
                          <div className="dropdown-divider" />
                          <a className="dropdown-item text-danger" href="#!">
                            Remove
                          </a>
                        </div>
                      </div>
                    </div>
                    <div className="card-body d-flex flex-center flex-column">
                      {/* Find the JS file for the following chart at: src/js/charts/echarts/bandwidth-saved.js*/}
                      {/* If you are not using gulp based workflow, you can find the transpiled code at: public/assets/js/theme.js*/}
                      <div
                        className="echart-bandwidth-saved"
                        data-echart-responsive="true"
                      />
                      <div className="text-center mt-3">
                        <h6 className="fs-0 mb-1">
                          <span
                            className="fas fa-check text-success me-1"
                            data-fa-transform="shrink-2"
                          />
                          35.75 GB saved
                        </h6>
                        <p className="fs--1 mb-0">38.44 GB total bandwidth</p>
                      </div>
                    </div>
                    <div className="card-footer bg-light py-2">
                      <div className="row flex-between-center">
                        <div className="col-auto">
                          <select className="form-select form-select-sm">
                            <option>Last 6 Months</option>
                            <option>Last Year</option>
                            <option>Last 2 Year</option>
                          </select>
                        </div>
                        <div className="col-auto">
                          <a className="fs--1 font-sans-serif" href="#!">
                            Help
                          </a>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="col-xxl-6 px-xxl-2">
                  <div className="card h-100">
                    <div className="card-header bg-light py-2">
                      <div className="row flex-between-center">
                        <div className="col-auto">
                          <h6 className="mb-0">Top Products</h6>
                        </div>
                        <div className="col-auto d-flex">
                          <a className="btn btn-link btn-sm me-2" href="#!">
                            View Details
                          </a>
                          <div className="dropdown font-sans-serif btn-reveal-trigger">
                            <button
                              className="btn btn-link text-600 btn-sm dropdown-toggle dropdown-caret-none btn-reveal"
                              type="button"
                              id="dropdown-top-products"
                              data-bs-toggle="dropdown"
                              data-boundary="viewport"
                              aria-haspopup="true"
                              aria-expanded="false"
                            >
                              <span className="fas fa-ellipsis-h fs--2" />
                            </button>
                            <div
                              className="dropdown-menu dropdown-menu-end border py-2"
                              aria-labelledby="dropdown-top-products"
                            >
                              <a className="dropdown-item" href="#!">
                                View
                              </a>
                              <a className="dropdown-item" href="#!">
                                Export
                              </a>
                              <div className="dropdown-divider" />
                              <a
                                className="dropdown-item text-danger"
                                href="#!"
                              >
                                Remove
                              </a>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                    <div className="card-body h-100">
                      {/* Find the JS file for the following chart at: src/js/charts/echarts/top-products.js*/}
                      {/* If you are not using gulp based workflow, you can find the transpiled code at: public/assets/js/theme.js*/}
                      <div
                        className="echart-bar-top-products h-100"
                        data-echart-responsive="true"
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <footer className="footer">
              <div className="row g-0 justify-content-between fs--1 mt-4 mb-3">
                <div className="col-12 col-sm-auto text-center">
                  <p className="mb-0 text-600">
                    Powered by <strong>Dynamic Order Management System</strong>{" "}
                    <span className="d-none d-sm-inline-block">| </span>
                    <br className="d-sm-none" /> 2025 ©{" "}
                    <a href="https://github.com/YogTandel">YOG TANDEL</a>
                  </p>
                </div>
              </div>
            </footer>
          </div>
        )}
        <div
          className="modal fade"
          id="authentication-modal"
          tabIndex={-1}
          role="dialog"
          aria-labelledby="authentication-modal-label"
          aria-hidden="true"
        >
          <div className="modal-dialog mt-6" role="document">
            <div className="modal-content border-0">
              <div className="modal-header px-5 position-relative modal-shape-header bg-shape">
                <div className="position-relative z-index-1 light">
                  <h4
                    className="mb-0 text-white"
                    id="authentication-modal-label"
                  >
                    Register
                  </h4>
                  <p className="fs--1 mb-0 text-white">
                    Please create your free Falcon account
                  </p>
                </div>
                <button
                  className="btn-close btn-close-white position-absolute top-0 end-0 mt-2 me-2"
                  data-bs-dismiss="modal"
                  aria-label="Close"
                />
              </div>
              <div className="modal-body py-4 px-5">
                <form>
                  <div className="mb-3">
                    <label className="form-label" htmlFor="modal-auth-name">
                      Name
                    </label>
                    <input
                      className="form-control"
                      type="text"
                      autoComplete="on"
                      id="modal-auth-name"
                    />
                  </div>
                  <div className="mb-3">
                    <label className="form-label" htmlFor="modal-auth-email">
                      Email address
                    </label>
                    <input
                      className="form-control"
                      type="email"
                      autoComplete="on"
                      id="modal-auth-email"
                    />
                  </div>
                  <div className="row gx-2">
                    <div className="mb-3 col-sm-6">
                      <label
                        className="form-label"
                        htmlFor="modal-auth-password"
                      >
                        Password
                      </label>
                      <input
                        className="form-control"
                        type="password"
                        autoComplete="on"
                        id="modal-auth-password"
                      />
                    </div>
                    <div className="mb-3 col-sm-6">
                      <label
                        className="form-label"
                        htmlFor="modal-auth-confirm-password"
                      >
                        Confirm Password
                      </label>
                      <input
                        className="form-control"
                        type="password"
                        autoComplete="on"
                        id="modal-auth-confirm-password"
                      />
                    </div>
                  </div>
                  <div className="form-check">
                    <input
                      className="form-check-input"
                      type="checkbox"
                      id="modal-auth-register-checkbox"
                    />
                    <label
                      className="form-label"
                      htmlFor="modal-auth-register-checkbox"
                    >
                      I accept the <a href="#!">terms </a>and{" "}
                      <a href="#!">privacy policy</a>
                    </label>
                  </div>
                  <div className="mb-3">
                    <button
                      className="btn btn-primary d-block w-100 mt-3"
                      type="submit"
                      name="submit"
                    >
                      Register
                    </button>
                  </div>
                </form>
                <div className="position-relative mt-5">
                  <hr className="bg-300" />
                  <div className="divider-content-center">or register with</div>
                </div>
                <div className="row g-2 mt-2">
                  <div className="col-sm-6">
                    <a
                      className="btn btn-outline-google-plus btn-sm d-block w-100"
                      href="#"
                    >
                      <span
                        className="fab fa-google-plus-g me-2"
                        data-fa-transform="grow-8"
                      />{" "}
                      google
                    </a>
                  </div>
                  <div className="col-sm-6">
                    <a
                      className="btn btn-outline-facebook btn-sm d-block w-100"
                      href="#"
                    >
                      <span
                        className="fab fa-facebook-square me-2"
                        data-fa-transform="grow-8"
                      />{" "}
                      facebook
                    </a>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default MainPage;

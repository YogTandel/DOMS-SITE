import { Link, useNavigate } from "react-router-dom";

const Register = () => {
  const navigate = useNavigate();

  const handleRegister = (event) => {
    event.preventDefault();
    navigate("/");
  };
  return (
    <>
      <div className="main" id="top">
        <div className="container-fluid">
          <div className="row min-vh-100 flex-center g-0">
            <div className="col-lg-8 col-xxl-5 py-3 position-relative">
              <img
                className="bg-auth-circle-shape"
                src="img/icons/spot-illustrations/bg-shape.png"
                alt=""
                width={250}
              />
              <img
                className="bg-auth-circle-shape-2"
                src="img/icons/spot-illustrations/shape-1.png"
                alt=""
                width={150}
              />
              <div className="card overflow-hidden z-index-1">
                <div className="card-body p-0">
                  <div className="row g-0 h-100">
                    <div className="col-md-5 text-center bg-card-gradient">
                      <div className="position-relative p-4 pt-md-5 pb-md-7 light">
                        <div
                          className="bg-holder bg-auth-card-shape"
                          style={{
                            backgroundImage:
                              "url(img/icons/spot-illustrations/half-circle.png)",
                          }}
                        ></div>
                        {/*/.bg-holder*/}
                        <div className="z-index-1 position-relative">
                          <Link
                            className="link-light mb-4 font-sans-serif fs-4 d-inline-block fw-bolder"
                            to="/register"
                          >
                            Dashboard
                          </Link>
                          <p className="opacity-75 text-white">
                            With the power of Falcon, you can now focus only on
                            functionaries for your digital products, while
                            leaving the UI design on us!
                          </p>
                        </div>
                      </div>
                      <div className="mt-3 mb-4 mt-md-4 mb-md-5 light">
                        <p className="pt-3 text-white">
                          Have an account?
                          <br />
                          <Link
                            className="btn btn-outline-light mt-2 px-4"
                            to="/"
                          >
                            Log In
                          </Link>
                        </p>
                      </div>
                    </div>
                    <div className="col-md-7 d-flex flex-center">
                      <div className="p-4 p-md-5 flex-grow-1">
                        <h3>Register</h3>
                        <form>
                          <div className="mb-3">
                            <label className="form-label" htmlFor="card-name">
                              Name
                            </label>
                            <input
                              className="form-control"
                              type="text"
                              autoComplete="on"
                              id="card-name"
                            />
                          </div>
                          <div className="mb-3">
                            <label className="form-label" htmlFor="card-email">
                              Email address
                            </label>
                            <input
                              className="form-control"
                              type="email"
                              autoComplete="on"
                              id="card-email"
                            />
                          </div>
                          <div className="row gx-2">
                            <div className="mb-3 col-sm-6">
                              <label
                                className="form-label"
                                htmlFor="card-password"
                              >
                                Password
                              </label>
                              <input
                                className="form-control"
                                type="password"
                                autoComplete="on"
                                id="card-password"
                              />
                            </div>
                            <div className="mb-3 col-sm-6">
                              <label
                                className="form-label"
                                htmlFor="card-confirm-password"
                              >
                                Confirm Password
                              </label>
                              <input
                                className="form-control"
                                type="password"
                                autoComplete="on"
                                id="card-confirm-password"
                              />
                            </div>
                          </div>
                          <div className="form-check">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              id="card-register-checkbox"
                            />
                            <label
                              className="form-label"
                              htmlFor="card-register-checkbox"
                            >
                              I accept the <a href="#!">terms </a>and
                              <a href="#!">privacy policy</a>
                            </label>
                          </div>
                          <div className="mb-3">
                            <button
                              className="btn btn-primary d-block w-100 mt-3"
                              type="submit"
                              name="submit"
                              onClick={handleRegister}
                            >
                              Register
                            </button>
                          </div>
                        </form>
                        <div className="position-relative mt-4">
                          <hr className="bg-300" />
                          <div className="divider-content-center">
                            or register with
                          </div>
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
          </div>
        </div>
      </div>
      <div className="main" id="top">
        <div className="container-fluid">
          <div className="row min-vh-100 flex-center g-0">
            <div className="col-lg-8 col-xxl-5 py-3 position-relative">
              <img
                className="bg-auth-circle-shape"
                src="/img/icons/spot-illustrations/bg-shape.png"
                alt=""
                width={250}
              />
              <img
                className="bg-auth-circle-shape-2"
                src="img/icons/spot-illustrations/shape-1.png"
                alt=""
                width={150}
              />
              <div className="card overflow-hidden z-index-1">
                <div className="card-body p-0">
                  <div className="row g-0 h-100">
                    <div className="col-md-5 text-center bg-card-gradient">
                      <div className="position-relative p-4 pt-md-5 pb-md-7 light">
                        <div
                          className="bg-holder bg-auth-card-shape"
                          style={{
                            backgroundImage:
                              "url(img/icons/spot-illustrations/half-circle.png)",
                          }}
                        ></div>
                        {/*/.bg-holder*/}
                        <div className="z-index-1 position-relative">
                          <a
                            className="link-light mb-4 font-sans-serif fs-4 d-inline-block fw-bolder"
                            href="../../../index.html"
                          >
                            falcon
                          </a>
                          <p className="opacity-75 text-white">
                            With the power of Falcon, you can now focus only on
                            functionaries for your digital products, while
                            leaving the UI design on us!
                          </p>
                        </div>
                      </div>
                      <div className="mt-3 mb-4 mt-md-4 mb-md-5 light">
                        <p className="text-white">
                          Don&apos;t have an account?
                          <br />
                          <a
                            className="text-decoration-underline link-light"
                            href="../../../pages/authentication/card/register.html"
                          >
                            Get started!
                          </a>
                        </p>
                        <p className="mb-0 mt-4 mt-md-5 fs--1 fw-semi-bold text-white opacity-75">
                          Read our{" "}
                          <a
                            className="text-decoration-underline text-white"
                            href="#!"
                          >
                            terms
                          </a>{" "}
                          and{" "}
                          <a
                            className="text-decoration-underline text-white"
                            href="#!"
                          >
                            conditions{" "}
                          </a>
                        </p>
                      </div>
                    </div>
                    <div className="col-md-7 d-flex flex-center">
                      <div className="p-4 p-md-5 flex-grow-1">
                        <div className="row flex-between-center">
                          <div className="col-auto">
                            <h3>Account Login</h3>
                          </div>
                        </div>
                        <form>
                          <div className="mb-3">
                            <label className="form-label" htmlFor="card-email">
                              Email address
                            </label>
                            <input
                              className="form-control"
                              id="card-email"
                              type="email"
                            />
                          </div>
                          <div className="mb-3">
                            <div className="d-flex justify-content-between">
                              <label
                                className="form-label"
                                htmlFor="card-password"
                              >
                                Password
                              </label>
                            </div>
                            <input
                              className="form-control"
                              id="card-password"
                              type="password"
                            />
                          </div>
                          <div className="row flex-between-center">
                            <div className="col-auto">
                              <div className="form-check mb-0">
                                <input
                                  className="form-check-input"
                                  type="checkbox"
                                  id="card-checkbox"
                                  defaultChecked="checked"
                                />
                                <label
                                  className="form-check-label mb-0"
                                  htmlFor="card-checkbox"
                                >
                                  Remember me
                                </label>
                              </div>
                            </div>
                            <div className="col-auto">
                              <Link className="fs--1" to="/forgotpassword">
                                Forgot Password?
                              </Link>
                            </div>
                          </div>
                          <div className="mb-3">
                            <button
                              className="btn btn-primary d-block w-100 mt-3"
                              type="submit"
                              name="submit"
                            >
                              Log in
                            </button>
                          </div>
                        </form>
                        <div className="position-relative mt-4">
                          <hr className="bg-300" />
                          <div className="divider-content-center">
                            or log in with
                          </div>
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
          </div>
        </div>
      </div>
      <div
        className="offcanvas offcanvas-end settings-panel border-0"
        id="settings-offcanvas"
        tabIndex={-1}
        aria-labelledby="settings-offcanvas"
      >
        <div className="offcanvas-header settings-panel-header bg-shape">
          <div className="z-index-1 py-1 light">
            <h5 className="text-white">
              {" "}
              <span className="fas fa-palette me-2 fs-0" />
              Settings
            </h5>
            <p className="mb-0 fs--1 text-white opacity-75">
              {" "}
              Set your own customized style
            </p>
          </div>
          <button
            className="btn-close btn-close-white z-index-1 mt-0"
            type="button"
            data-bs-dismiss="offcanvas"
            aria-label="Close"
          />
        </div>
        <div
          className="offcanvas-body scrollbar-overlay px-card"
          id="themeController"
        >
          <h5 className="fs-0">Color Scheme</h5>
          <p className="fs--1">Choose the perfect color mode for your app.</p>
          <div className="btn-group d-block w-100 btn-group-navbar-style">
            <div className="row gx-2">
              <div className="col-6">
                <input
                  className="btn-check"
                  id="themeSwitcherLight"
                  name="theme-color"
                  type="radio"
                  defaultValue="light"
                  data-theme-control="theme"
                />
                <label
                  className="btn d-inline-block btn-navbar-style fs--1"
                  htmlFor="themeSwitcherLight"
                >
                  {" "}
                  <span className="hover-overlay mb-2 rounded d-block">
                    <img
                      className="img-fluid img-prototype mb-0"
                      src="img/generic/falcon-mode-default.jpg"
                      alt=""
                    />
                  </span>
                  <span className="label-text">Light</span>
                </label>
              </div>
              <div className="col-6">
                <input
                  className="btn-check"
                  id="themeSwitcherDark"
                  name="theme-color"
                  type="radio"
                  defaultValue="dark"
                  data-theme-control="theme"
                />
                <label
                  className="btn d-inline-block btn-navbar-style fs--1"
                  htmlFor="themeSwitcherDark"
                >
                  {" "}
                  <span className="hover-overlay mb-2 rounded d-block">
                    <img
                      className="img-fluid img-prototype mb-0"
                      src="img/generic/falcon-mode-dark.jpg"
                      alt=""
                    />
                  </span>
                  <span className="label-text">Dark</span>
                </label>
              </div>
            </div>
          </div>
          <hr />
          <div className="d-flex justify-content-between">
            <div className="d-flex align-items-start">
              <img
                className="me-2"
                src="img/icons/left-arrow-from-left.svg"
                width={20}
                alt=""
              />
              <div className="flex-1">
                <h5 className="fs-0">RTL Mode</h5>
                <p className="fs--1 mb-0">Switch your language direction </p>
                <a
                  className="fs--1"
                  href="../../../documentation/customization/configuration.html"
                >
                  RTL Documentation
                </a>
              </div>
            </div>
            <div className="form-check form-switch">
              <input
                className="form-check-input ms-0"
                id="mode-rtl"
                type="checkbox"
                data-theme-control="isRTL"
              />
            </div>
          </div>
          <hr />
          <div className="d-flex justify-content-between">
            <div className="d-flex align-items-start">
              <img
                className="me-2"
                src="img/icons/arrows-h.svg"
                width={20}
                alt=""
              />
              <div className="flex-1">
                <h5 className="fs-0">Fluid Layout</h5>
                <p className="fs--1 mb-0">Toggle container layout system </p>
                <a
                  className="fs--1"
                  href="../../../documentation/customization/configuration.html"
                >
                  Fluid Documentation
                </a>
              </div>
            </div>
            <div className="form-check form-switch">
              <input
                className="form-check-input ms-0"
                id="mode-fluid"
                type="checkbox"
                data-theme-control="isFluid"
              />
            </div>
          </div>
          <hr />
          <div className="d-flex align-items-start">
            <img
              className="me-2"
              src="img/icons/paragraph.svg"
              width={20}
              alt=""
            />
            <div className="flex-1">
              <h5 className="fs-0 d-flex align-items-center">
                Navigation Position{" "}
              </h5>
              <p className="fs--1 mb-2">
                Select a suitable navigation system for your web application{" "}
              </p>
              <div>
                <div className="form-check form-check-inline">
                  <input
                    className="form-check-input"
                    id="option-navbar-vertical"
                    type="radio"
                    name="navbar"
                    defaultValue="vertical"
                    data-page-url="../../../modules/components/navs-and-tabs/vertical-navbar.html"
                    data-theme-control="navbarPosition"
                  />
                  <label
                    className="form-check-label"
                    htmlFor="option-navbar-vertical"
                  >
                    Vertical
                  </label>
                </div>
                <div className="form-check form-check-inline">
                  <input
                    className="form-check-input"
                    id="option-navbar-top"
                    type="radio"
                    name="navbar"
                    defaultValue="top"
                    data-page-url="../../../modules/components/navs-and-tabs/top-navbar.html"
                    data-theme-control="navbarPosition"
                  />
                  <label
                    className="form-check-label"
                    htmlFor="option-navbar-top"
                  >
                    Top
                  </label>
                </div>
                <div className="form-check form-check-inline me-0">
                  <input
                    className="form-check-input"
                    id="option-navbar-combo"
                    type="radio"
                    name="navbar"
                    defaultValue="combo"
                    data-page-url="../../../modules/components/navs-and-tabs/combo-navbar.html"
                    data-theme-control="navbarPosition"
                  />
                  <label
                    className="form-check-label"
                    htmlFor="option-navbar-combo"
                  >
                    Combo
                  </label>
                </div>
              </div>
            </div>
          </div>
          <hr />
          <h5 className="fs-0 d-flex align-items-center">
            Vertical Navbar Style
          </h5>
          <p className="fs--1 mb-0">
            Switch between styles for your vertical navbar{" "}
          </p>
          <p>
            {" "}
            <a
              className="fs--1"
              href="../../../modules/components/navs-and-tabs/vertical-navbar.html#navbar-styles"
            >
              See Documentation
            </a>
          </p>
          <div className="btn-group d-block w-100 btn-group-navbar-style">
            <div className="row gx-2">
              <div className="col-6">
                <input
                  className="btn-check"
                  id="navbar-style-transparent"
                  type="radio"
                  name="navbarStyle"
                  defaultValue="transparent"
                  data-theme-control="navbarStyle"
                />
                <label
                  className="btn d-block w-100 btn-navbar-style fs--1"
                  htmlFor="navbar-style-transparent"
                >
                  {" "}
                  <img
                    className="img-fluid img-prototype"
                    src="img/generic/default.png"
                    alt=""
                  />
                  <span className="label-text"> Transparent</span>
                </label>
              </div>
              <div className="col-6">
                <input
                  className="btn-check"
                  id="navbar-style-inverted"
                  type="radio"
                  name="navbarStyle"
                  defaultValue="inverted"
                  data-theme-control="navbarStyle"
                />
                <label
                  className="btn d-block w-100 btn-navbar-style fs--1"
                  htmlFor="navbar-style-inverted"
                >
                  {" "}
                  <img
                    className="img-fluid img-prototype"
                    src="img/generic/inverted.png"
                    alt=""
                  />
                  <span className="label-text"> Inverted</span>
                </label>
              </div>
              <div className="col-6">
                <input
                  className="btn-check"
                  id="navbar-style-card"
                  type="radio"
                  name="navbarStyle"
                  defaultValue="card"
                  data-theme-control="navbarStyle"
                />
                <label
                  className="btn d-block w-100 btn-navbar-style fs--1"
                  htmlFor="navbar-style-card"
                >
                  {" "}
                  <img
                    className="img-fluid img-prototype"
                    src="img/generic/card.png"
                    alt=""
                  />
                  <span className="label-text"> Card</span>
                </label>
              </div>
              <div className="col-6">
                <input
                  className="btn-check"
                  id="navbar-style-vibrant"
                  type="radio"
                  name="navbarStyle"
                  defaultValue="vibrant"
                  data-theme-control="navbarStyle"
                />
                <label
                  className="btn d-block w-100 btn-navbar-style fs--1"
                  htmlFor="navbar-style-vibrant"
                >
                  {" "}
                  <img
                    className="img-fluid img-prototype"
                    src="img/generic/vibrant.png"
                    alt=""
                  />
                  <span className="label-text"> Vibrant</span>
                </label>
              </div>
            </div>
          </div>
          <div className="text-center mt-5">
            <img
              className="mb-4"
              src="img/icons/spot-illustrations/47.png"
              alt=""
              width={120}
            />
            <h5>Like What You See?</h5>
            <p className="fs--1">
              Get Falcon now and create beautiful dashboards with hundreds of
              widgets.
            </p>
            <a
              className="mb-3 btn btn-primary"
              href="https://themes.getbootstrap.com/product/falcon-admin-dashboard-webapp-template/"
              target="_blank"
            >
              Purchase
            </a>
          </div>
        </div>
      </div>
      <a
        className="card setting-toggle"
        href="#settings-offcanvas"
        data-bs-toggle="offcanvas"
      >
        <div className="card-body d-flex align-items-center py-md-2 px-2 py-1">
          <div
            className="bg-soft-primary position-relative rounded-start"
            style={{ height: 34, width: 28 }}
          >
            <div className="settings-popover">
              <span className="ripple">
                <span className="fa-spin position-absolute all-0 d-flex flex-center">
                  <span className="icon-spin position-absolute all-0 d-flex flex-center">
                    <svg
                      width={20}
                      height={20}
                      viewBox="0 0 20 20"
                      fill="none"
                      xmlns="http://www.w3.org/2000/svg"
                    >
                      <path
                        d="M19.7369 12.3941L19.1989 12.1065C18.4459 11.7041 18.0843 10.8487 18.0843 9.99495C18.0843 9.14118 18.4459 8.28582 19.1989 7.88336L19.7369 7.59581C19.9474 7.47484 20.0316 7.23291 19.9474 7.03131C19.4842 5.57973 18.6843 4.28943 17.6738 3.20075C17.5053 3.03946 17.2527 2.99914 17.0422 3.12011L16.393 3.46714C15.6883 3.84379 14.8377 3.74529 14.1476 3.3427C14.0988 3.31422 14.0496 3.28621 14.0002 3.25868C13.2568 2.84453 12.7055 2.10629 12.7055 1.25525V0.70081C12.7055 0.499202 12.5371 0.297594 12.2845 0.257272C10.7266 -0.105622 9.16879 -0.0653007 7.69516 0.257272C7.44254 0.297594 7.31623 0.499202 7.31623 0.70081V1.23474C7.31623 2.09575 6.74999 2.8362 5.99824 3.25599C5.95774 3.27861 5.91747 3.30159 5.87744 3.32493C5.15643 3.74527 4.26453 3.85902 3.53534 3.45302L2.93743 3.12011C2.72691 2.99914 2.47429 3.03946 2.30587 3.20075C1.29538 4.28943 0.495411 5.57973 0.0322686 7.03131C-0.051939 7.23291 0.0322686 7.47484 0.242788 7.59581L0.784376 7.8853C1.54166 8.29007 1.92694 9.13627 1.92694 9.99495C1.92694 10.8536 1.54166 11.6998 0.784375 12.1046L0.242788 12.3941C0.0322686 12.515 -0.051939 12.757 0.0322686 12.9586C0.495411 14.4102 1.29538 15.7005 2.30587 16.7891C2.47429 16.9504 2.72691 16.9907 2.93743 16.8698L3.58669 16.5227C4.29133 16.1461 5.14131 16.2457 5.8331 16.6455C5.88713 16.6767 5.94159 16.7074 5.99648 16.7375C6.75162 17.1511 7.31623 17.8941 7.31623 18.7552V19.2891C7.31623 19.4425 7.41373 19.5959 7.55309 19.696C7.64066 19.7589 7.74815 19.7843 7.85406 19.8046C9.35884 20.0925 10.8609 20.0456 12.2845 19.7729C12.5371 19.6923 12.7055 19.4907 12.7055 19.2891V18.7346C12.7055 17.8836 13.2568 17.1454 14.0002 16.7312C14.0496 16.7037 14.0988 16.6757 14.1476 16.6472C14.8377 16.2446 15.6883 16.1461 16.393 16.5227L17.0422 16.8698C17.2527 16.9907 17.5053 16.9504 17.6738 16.7891C18.7264 15.7005 19.4842 14.4102 19.9895 12.9586C20.0316 12.757 19.9474 12.515 19.7369 12.3941ZM10.0109 13.2005C8.1162 13.2005 6.64257 11.7893 6.64257 9.97478C6.64257 8.20063 8.1162 6.74905 10.0109 6.74905C11.8634 6.74905 13.3792 8.20063 13.3792 9.97478C13.3792 11.7893 11.8634 13.2005 10.0109 13.2005Z"
                        fill="#2A7BE4"
                      />
                    </svg>
                  </span>
                </span>
              </span>
            </div>
          </div>
          <small className="text-uppercase text-primary fw-bold bg-soft-primary py-2 pe-2 ps-1 rounded-end">
            customize
          </small>
        </div>
      </a>
    </>
  );
};

export default Register;

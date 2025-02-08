<ul className="nav collapse show" id="dashboard">
  <li className="nav-item">
    <a
      className="nav-link active"
      //   onClick={() => handelAdminActionChange("Main")}
      data-bs-toggle="collapse"
      aria-expanded="false"
    >
      <div className="d-flex align-items-center">
        <span className="nav-link-text ps-1">Main</span>
      </div>
    </a>

    <ul className="nav collapse false" id="admin">
      <li className="nav-item">
        <a
          className="nav-link"
          // onClick={() => handelAdminActionChange("create")}
          data-bs-toggle="collapse"
          aria-expanded="false"
          aria-controls="admin"
        >
          <div className="d-flex align-items-center">
            <span className="nav-link-text ps-1">Create Admin</span>
          </div>
        </a>
        <a
          className="nav-link"
          // onClick={() => handelAdminActionChange("block")}
          data-bs-toggle="collapse"
          aria-expanded="false"
          aria-controls="admin"
        >
          <div className="d-flex align-items-center">
            <span className="nav-link-text ps-1">Block Admin</span>
          </div>
        </a>
        <a
          className="nav-link"
          // onClick={() =>
          //   handelAdminActionChange("changePassword")
          // }
          data-bs-toggle="collapse"
          aria-expanded="false"
          aria-controls="admin"
        >
          <div className="d-flex align-items-center">
            <span className="nav-link-text ps-1">Change Admin Password</span>
          </div>
        </a>
      </li>
    </ul>
  </li>
  {/* <div className="row g-3 mb-3">
    {adminAction && (
      <div className="admin-action-section mt-3">
        {adminAction === "create" && (
          <div
            className="d-flex justify-content-center align-items-center vh-100 "
            style={{ padding: "20px" }}
          >
            <div className="card shadow-sm" style={{ width: "400px" }}>
              <div className="card-header bg-primary text-white text-center">
                <h5 className="mb-0">Create Admin</h5>
              </div>
              <div className="card-body">
                <form>
                  <div className="mb-3">
                    <label htmlFor="adminName" className="form-label">
                      Admin Name
                    </label>
                    <input
                      type="text"
                      id="adminName"
                      placeholder="Enter admin name"
                      className="form-control"
                    />
                  </div>
                  <div className="mb-3">
                    <label htmlFor="adminEmail" className="form-label">
                      Admin Email
                    </label>
                    <input
                      type="email"
                      id="adminEmail"
                      placeholder="Enter admin email"
                      className="form-control"
                    />
                  </div>
                  <button type="submit" className="btn btn-primary w-100">
                    Submit
                  </button>
                </form>
              </div>
            </div>
          </div>
        )}
        {adminAction === "block" && (
          <div>
            <h5>Block Admin</h5>
            <form>
              <input
                type="text"
                placeholder="Admin Name/Email"
                className="form-control mb-2"
              />
              <button type="submit" className="btn btn-danger">
                Block
              </button>
            </form>
          </div>
        )}
        {adminAction === "changePassword" && (
          <div>
            <h5>Change Admin Password</h5>
            <form>
              <input
                type="password"
                placeholder="New Password"
                className="form-control mb-2"
              />
              <button type="submit" className="btn btn-danger">
                Chenge Password
              </button>
            </form>
          </div>
        )}
      </div>
    )}
  </div> */}
</ul>


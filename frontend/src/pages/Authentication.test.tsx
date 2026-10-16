import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it, type Mock, vi } from "vitest";
import { useSystem } from "@/apis/hooks";
import { customRender, screen } from "@/tests";
import server from "@/tests/mocks/node";
import Authentication from "./Authentication";

vi.mock("@/apis/hooks", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/apis/hooks")>();
  return {
    ...actual,
    useSystem: vi.fn(),
  };
});

const mockLogin = vi.fn();

const setupUseSystem = (isLoggingIn = false) => {
  const mocked = useSystem as Mock;
  mocked.mockReturnValue({
    login: mockLogin,
    logout: vi.fn(),
    shutdown: vi.fn(),
    restart: vi.fn(),
    isMutating: isLoggingIn,
    isLoggingIn,
  });
};

describe("Authentication", () => {
  beforeEach(() => {
    mockLogin.mockClear();
    window.history.pushState({}, "", "/");
    window.Bazarr = {
      baseUrl: "",
      canUpdate: false,
      hasUpdate: false,
      oidcEnabled: false,
      oidcDisplayName: "Login with OIDC",
    };
  });

  it("renders login form", () => {
    setupUseSystem();
    customRender(<Authentication />);

    expect(screen.getByRole("heading", { name: "Bazarr" })).toBeInTheDocument();
    expect(
      screen.getByLabelText(/Username/i, { selector: "input" }),
    ).toBeInTheDocument();
    expect(
      screen.getByLabelText(/Password/i, { selector: "input" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Login" })).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: /Login with OIDC/i }),
    ).not.toBeInTheDocument();
  });

  it("submits credentials", async () => {
    setupUseSystem();
    customRender(<Authentication />);

    const user = userEvent.setup();
    await user.type(
      screen.getByLabelText(/Username/i, { selector: "input" }),
      "admin",
    );
    await user.type(
      screen.getByLabelText(/Password/i, { selector: "input" }),
      "secret",
    );
    await user.click(screen.getByRole("button", { name: "Login" }));

    expect(mockLogin).toHaveBeenCalledWith(
      { username: "admin", password: "secret" },
      expect.any(Object),
    );
  });

  it("disables form while logging in", () => {
    setupUseSystem(true);
    customRender(<Authentication />);

    expect(
      screen.getByLabelText(/Username/i, { selector: "input" }),
    ).toBeDisabled();
    expect(
      screen.getByLabelText(/Password/i, { selector: "input" }),
    ).toBeDisabled();
    expect(screen.getByRole("button", { name: "Login" })).toBeDisabled();
  });

  it("shows inline error when login fails", async () => {
    mockLogin.mockImplementation((_, { onError }) => {
      onError(new Error("Authentication failed"));
    });
    setupUseSystem();

    customRender(<Authentication />);

    const user = userEvent.setup();
    await user.type(
      screen.getByLabelText(/Username/i, { selector: "input" }),
      "admin",
    );
    await user.type(
      screen.getByLabelText(/Password/i, { selector: "input" }),
      "secret",
    );
    await user.click(screen.getByRole("button", { name: "Login" }));

    expect(
      await screen.findByText("Authentication failed"),
    ).toBeInTheDocument();
  });

  it("renders OIDC login button when oidc is enabled via API", async () => {
    server.use(
      http.get("/api/auth/oidc/config", () => {
        return HttpResponse.json({
          enabled: true,
          displayName: "Login with Authelia",
        });
      }),
    );
    setupUseSystem();

    customRender(<Authentication />);

    const oidcButton = await screen.findByRole("link", {
      name: "Login with Authelia",
    });
    expect(oidcButton).toBeInTheDocument();
    expect(oidcButton).toHaveAttribute("href", "/api/auth/oidc/login");
    expect(screen.getByText("or")).toBeInTheDocument();
  });

  it("renders OIDC button when enabled via window.Bazarr", async () => {
    window.Bazarr = {
      baseUrl: "",
      canUpdate: false,
      hasUpdate: false,
      oidcEnabled: true,
      oidcDisplayName: "Single Sign-On",
    };
    server.use(
      http.get("/api/auth/oidc/config", () => {
        return HttpResponse.json({
          enabled: true,
          displayName: "Single Sign-On",
        });
      }),
    );
    setupUseSystem();

    customRender(<Authentication />);

    const oidcButton = await screen.findByRole("link", {
      name: "Single Sign-On",
    });
    expect(oidcButton).toBeInTheDocument();
  });

  it("displays error message from URL search params", async () => {
    window.history.pushState({}, "", "/?error=access_denied");
    setupUseSystem();

    customRender(<Authentication />);

    expect(
      await screen.findByText("Access denied by OIDC Identity Provider."),
    ).toBeInTheDocument();
  });

  it("displays unauthorized group error from URL search params", async () => {
    window.history.pushState({}, "", "/?error=unauthorized_group");
    setupUseSystem();

    customRender(<Authentication />);

    expect(
      await screen.findByText(
        "Access denied: your account is not a member of the required admin group.",
      ),
    ).toBeInTheDocument();
  });

  it("displays various other error messages from URL search params", async () => {
    window.history.pushState({}, "", "/?error=invalid_request");
    setupUseSystem();
    const { unmount } = customRender(<Authentication />);
    expect(
      await screen.findByText(
        "OIDC authentication error: Invalid request parameters.",
      ),
    ).toBeInTheDocument();
    unmount();

    window.history.pushState({}, "", "/?error=invalid_state");
    const { unmount: unmount2 } = customRender(<Authentication />);
    expect(
      await screen.findByText(
        "OIDC authentication error: State mismatch or session expired.",
      ),
    ).toBeInTheDocument();
    unmount2();

    window.history.pushState({}, "", "/?error=oidc_disabled");
    const { unmount: unmount3 } = customRender(<Authentication />);
    expect(
      await screen.findByText(
        "OIDC login is currently disabled on this server.",
      ),
    ).toBeInTheDocument();
    unmount3();

    window.history.pushState({}, "", "/?error=custom_error");
    customRender(<Authentication />);
    expect(
      await screen.findByText("OIDC error: custom_error"),
    ).toBeInTheDocument();
  });

  it("handles fetch failure gracefully", async () => {
    server.use(
      http.get("/api/auth/oidc/config", () => {
        return HttpResponse.error();
      }),
    );
    setupUseSystem();

    customRender(<Authentication />);
    expect(screen.getByRole("button", { name: "Login" })).toBeInTheDocument();
  });
});

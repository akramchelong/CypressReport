// +build windows

package auth

import (
	"errors"
	"fmt"
	"unsafe"

	"gitlab.se.axis.com/e2e/iam/onprem/oidc-win/internal/logger"
	"golang.org/x/sys/windows"
)

// LoginHandler provide function for logging in
type LoginHandler struct{}

// Group contains nice name and sid for user group
type Group struct {
	NiceName string
	SID      string
}

const (
	LOGON32_LOGON_NETWORK    = 0x3
	LOGON32_PROVIDER_DEFAULT = 0x0
	LG_INCLUDE_INDIRECT      = 0x1
	MAX_PREFERRED_LENGTH     = 0xFFFFFFFF
)

// Verify logs on a user to the local windows system and returns the user SID.
// Returns an error if authentication failed. Returns user sid if credentials
// are valid.
func (LoginHandler) Verify(username, domain, password string) (string, error) {
	return logonLocalUser(username, domain, password)
}

// logonLocalUser authenticates a user and returns the user sid if credentials
// are correct. Returns an error if credentials are invalid or other error
// occurred.
func logonLocalUser(user, domain, password string) (string, error) {
	var token windows.Handle
	u := stringToCharPtr(user)
	d := stringToCharPtr(domain)
	p := stringToCharPtr(password)

	err := logonUserA(u, d, p, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &token)
	if err != nil {
		return "", err
	}

	userSID, err := getUserSID(token)
	if err != nil {
		logger.Error("Error when getUserSID(), %q", err.Error())
		return "", err
	}
	logger.Debug("logonLocalUser: Token is %q", userSID)

	return userSID, nil
}

func getUserSID(token windows.Handle) (string, error) {
	tokenUser, err := windows.Token(token).GetTokenUser()
	if err != nil {
		logger.Info("Could not get token user from tokenHandle")
		return "", err
	}

	return tokenUser.User.Sid.String(), nil
}

func (LoginHandler) GetUserGroups(username string) ([]Group, error) {
	var p0 *byte
	var entriesRead, totalEntries uint32
	u, _ := windows.UTF16PtrFromString(username)
	defer func() { _ = windows.NetApiBufferFree(p0) }()

	err := netUserGetLocalGroups(nil, u, 0, LG_INCLUDE_INDIRECT, &p0, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	logger.Debug("Fetched user groups for user %s", username)
	type LocalGroupUserInfo0 struct {
		Name *uint16
	}

	if entriesRead == 0 {
		return nil, fmt.Errorf("NetUserGetLocalGroups() returned an empty list for username: %s", username)
	}

	userGroups := []Group{}

	// Extract the group names from p0 using a full slice expression
	entries := (*[1024]LocalGroupUserInfo0)(unsafe.Pointer(p0))[:entriesRead:entriesRead]
	for _, entry := range entries {
		if entry.Name == nil {
			continue
		}
		plain := windows.UTF16PtrToString(entry.Name)

		sid, err := lookupGroupName(plain)
		if err != nil {
			return nil, err
		}
		userGroups = append(userGroups, Group{
			plain,
			sid,
		})
	}

	return userGroups, nil
}

// logonUserA checks username, domain and password against the Windows API.
// Returns an error if user login failed or credentials is incorrect.
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera
// LPCSTR means the string needs to be a regular char, i.e. UTF-8
//
// LogonUserA(
//   LPCSTR  lpszUsername,
//   LPCSTR  lpszDomain,
//   LPCSTR  lpszPassword,
//   DWORD   dwLogonType,
//   DWORD   dwLogonProvider,
//   PHANDLE phToken
// );
func logonUserA(user *uint8, domain *uint8, password *uint8, logonType uint32, logonProvider uint32, handle *windows.Handle) error {
	dll := windows.NewLazySystemDLL("Advapi32.dll")
	if dll.Load() != nil {
		return errors.New("Failed to load Advapi32.dll.")
	}
	LogonUserAFunc := dll.NewProc("LogonUserA")
	r0, r1, _ := LogonUserAFunc.Call(
		uintptr(unsafe.Pointer(user)),
		uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(password)),
		uintptr(logonType),
		uintptr(logonProvider),
		uintptr(unsafe.Pointer(handle)),
	)
	logger.Debug("logonUserA: r0: %v, r1: %v", r0, r1)
	// If the LogonUserA fails, it returns zero.
	if r0 == 0 {
		// return custom error instead of err due to the risk of user
		// credentials leaking through the error from LogonUserA.
		return errors.New("Call to LogonUserA failed. ")
	}
	return nil
}

// netUserGetLocalGroups retrieves the users groups by asking the Windows API
// https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusergetlocalgroups
// LPCWSTR mean the string needs to be a wide character, i.e. UTF-16
//
// NetUserGetLocalGroups(
//   LPCWSTR servername,
//   LPCWSTR username,
//   DWORD   level,
//   DWORD   flags,
//   LPBYTE  *bufptr,
//   DWORD   prefmaxlen,
//   LPDWORD entriesread,
//   LPDWORD totalentries
// );
func netUserGetLocalGroups(serverName *uint16, userName *uint16, level uint32, flags uint32, buf **byte, prefMaxLen uint32, entriesRead *uint32, totalEntries *uint32) error {
	dll := windows.NewLazySystemDLL("Netapi32.dll")
	if dll.Load() != nil {
		return errors.New("Failed to load Netapi32.dll.")
	}
	netUserGetLocalGroupsFunc := dll.NewProc("NetUserGetLocalGroups")
	r0, r1, err := netUserGetLocalGroupsFunc.Call(
		uintptr(unsafe.Pointer(serverName)),
		uintptr(unsafe.Pointer(userName)),
		uintptr(level),
		uintptr(flags),
		uintptr(unsafe.Pointer(buf)),
		uintptr(prefMaxLen),
		uintptr(unsafe.Pointer(entriesRead)),
		uintptr(unsafe.Pointer(totalEntries)),
	)
	logger.Debug("netUserGetLocalGroups - r0: %d, r1: %d, err: %s", r0, r1, err)
	if r0 != 0 {
		return windows.Errno(r0)
	}
	return nil
}

func lookupGroupName(groupname string) (string, error) {
	sid, _, t, err := windows.LookupSID("", groupname)
	if err != nil {
		return "", err
	}
	// https://msdn.microsoft.com/en-us/library/cc245478.aspx#gt_0387e636-5654-4910-9519-1f8326cf5ec0
	// The SidType need to be one of (Group, WellKnownGroup, Alias) in order to be a group SID
	if t != windows.SidTypeGroup && t != windows.SidTypeWellKnownGroup && t != windows.SidTypeAlias {
		return "", fmt.Errorf("lookupGroupName: should be group account type, not %d", t)
	}

	return sid.String(), nil
}

func stringToCharPtr(str string) *uint8 {
	chars := append([]byte(str), 0)
	return &chars[0]
}

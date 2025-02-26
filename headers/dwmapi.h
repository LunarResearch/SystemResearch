#ifndef _DWMAPI_H
#define _DWMAPI_H

#if __POCC__ >= 500
#pragma once
#endif

/* Windows Desktop Window Manager API definitions (Vista) */

#ifndef DWMAPI
#define DWMAPI         EXTERN_C DECLSPEC_IMPORT HRESULT STDAPICALLTYPE
#define DWMAPI_(type)  EXTERN_C DECLSPEC_IMPORT type STDAPICALLTYPE
#endif /* DWMAPI */

#include <pshpack1.h>

#ifdef __cplusplus
extern "C" {
#endif

#if __POCC__ >= 290
#pragma warn(push)
#pragma warn(disable:2185)  /* Alignment of field 'x' can be less than the natural alignment */
#pragma warn(disable:2073)
#endif

#include <wtypes.h>
#include <uxtheme.h>

// Blur behind data structures
#define DWM_BB_ENABLE  0x00000001					// fEnable has been specified
#define DWM_BB_BLURREGION  0x00000002				// hRgnBlur has been specified
#define DWM_BB_TRANSITIONONMAXIMIZED  0x00000004	// fTransitionOnMaximized has been specified

#define DWM_TNP_RECTDESTINATION  0x00000001			// A value for the "rcDestination" member has been specified.
#define DWM_TNP_RECTSOURCE  0x00000002				// A value for the "rcSource" member has been specified.
#define DWM_TNP_OPACITY  0x00000004					// A value for the "opacity" member has been specified.
#define DWM_TNP_VISIBLE  0x00000008					// A value for the "fVisible" member has been specified.
#define DWM_TNP_SOURCECLIENTAREAONLY  0x00000010	// A value for the "fSourceClientAreaOnly" member has been specified.

#define DWM_FRAME_DURATION_DEFAULT  -1

#define DWMWA_COLOR_DEFAULT  0xFFFFFFFF	// Use this constant to reset any window part colors to the system default behavior
#define DWMWA_COLOR_NONE  0xFFFFFFFE	// Use this constant to specify that a window part should not be rendered

#define DWM_EC_DISABLECOMPOSITION  0
#define DWM_EC_ENABLECOMPOSITION  1

// Cloaked flags describing why a window is cloaked.
#define DWM_CLOAKED_APP  0x00000001
#define DWM_CLOAKED_SHELL  0x00000002
#define DWM_CLOAKED_INHERITED  0x00000004

typedef struct _DWM_BLURBEHIND {
    DWORD dwFlags;
    BOOL fEnable;
    HRGN hRgnBlur;
    BOOL fTransitionOnMaximized;
} DWM_BLURBEHIND, *PDWM_BLURBEHIND;

// Window attributes
enum DWMWINDOWATTRIBUTE {
	DWMWA_NCRENDERING_ENABLED = 1,              // [get] Is non-client rendering enabled/disabled
	DWMWA_NCRENDERING_POLICY,                   // [set] DWMNCRENDERINGPOLICY - Non-client rendering policy
	DWMWA_TRANSITIONS_FORCEDISABLED,            // [set] Potentially enable/forcibly disable transitions
	DWMWA_ALLOW_NCPAINT,                        // [set] Allow contents rendered in the non-client area to be visible on the DWM-drawn frame.
	DWMWA_CAPTION_BUTTON_BOUNDS,                // [get] Bounds of the caption button area in window-relative space.
	DWMWA_NONCLIENT_RTL_LAYOUT,                 // [set] Is non-client content RTL mirrored
	DWMWA_FORCE_ICONIC_REPRESENTATION,          // [set] Force this window to display iconic thumbnails.
	DWMWA_FLIP3D_POLICY,                        // [set] Designates how Flip3D will treat the window.
	DWMWA_EXTENDED_FRAME_BOUNDS,                // [get] Gets the extended frame bounds rectangle in screen space
	DWMWA_HAS_ICONIC_BITMAP,                    // [set] Indicates an available bitmap when there is no better thumbnail representation.
	DWMWA_DISALLOW_PEEK,                        // [set] Don't invoke Peek on the window.
	DWMWA_EXCLUDED_FROM_PEEK,                   // [set] LivePreview exclusion information
	DWMWA_CLOAK,                                // [set] Cloak or uncloak the window
	DWMWA_CLOAKED,                              // [get] Gets the cloaked state of the window
	DWMWA_FREEZE_REPRESENTATION,                // [set] BOOL, Force this window to freeze the thumbnail without live update
	DWMWA_PASSIVE_UPDATE_MODE,                  // [set] BOOL, Updates the window only when desktop composition runs for other reasons
	DWMWA_USE_HOSTBACKDROPBRUSH,                // [set] BOOL, Allows the use of host backdrop brushes for the window.
	DWMWA_USE_IMMERSIVE_DARK_MODE = 20,         // [set] BOOL, Allows a window to either use the accent color, or dark, according to the user Color Mode preferences.
	DWMWA_WINDOW_CORNER_PREFERENCE = 33,        // [set] WINDOW_CORNER_PREFERENCE, Controls the policy that rounds top-level window corners
	DWMWA_BORDER_COLOR,                         // [set] COLORREF, The color of the thin border around a top-level window
	DWMWA_CAPTION_COLOR,                        // [set] COLORREF, The color of the caption
	DWMWA_TEXT_COLOR,                           // [set] COLORREF, The color of the caption text
	DWMWA_VISIBLE_FRAME_BORDER_THICKNESS,       // [get] UINT, width of the visible border around a thick frame window
	DWMWA_SYSTEMBACKDROP_TYPE,                  // [get, set] SYSTEMBACKDROP_TYPE, Controls the system-drawn backdrop material of a window, including behind the non-client area.
	DWMWA_REDIRECTIONBITMAP_ALPHA,              // [set] BOOL, GDI redirection bitmap containspremultiplied alpha
	DWMWA_LAST
};

enum DWMNCRENDERINGPOLICY {
    DWMNCRP_USEWINDOWSTYLE,
    DWMNCRP_DISABLED,
    DWMNCRP_ENABLED,
    DWMNCRP_LAST
};

// Values designating how Flip3D treats a given window.
enum DWMFLIP3DWINDOWPOLICY {
    DWMFLIP3D_DEFAULT,		// Hide or include the window in Flip3D based on window style and visibility.
    DWMFLIP3D_EXCLUDEBELOW,	// Display the window under Flip3D and disabled.
    DWMFLIP3D_EXCLUDEABOVE,	// Display the window above Flip3D and enabled.
    DWMFLIP3D_LAST
};

typedef HANDLE HTHUMBNAIL;
typedef HTHUMBNAIL *PHTHUMBNAIL;

typedef struct _DWM_THUMBNAIL_PROPERTIES {
    DWORD dwFlags;				// Specifies which members of this struct have been specified
    RECT rcDestination;			// The area in the destination window where the thumbnail will be rendered
    RECT rcSource;				// The region of the source window to use as the thumbnail.  By default, the entire window is used as the thumbnail
    BYTE opacity;				// The opacity with which to render the thumbnail.  0 is fully transparent, while 255 is fully opaque.  The default value is 255
    BOOL fVisible;				// Whether the thumbnail should be visible.  The default is FALSE
    BOOL fSourceClientAreaOnly;	// Whether only the client area of the source window should be included in the thumbnail.  The default is FALSE
} DWM_THUMBNAIL_PROPERTIES, *PDWM_THUMBNAIL_PROPERTIES;

// Video enabling apis
typedef ULONGLONG DWM_FRAME_COUNT;
typedef ULONGLONG QPC_TIME;

typedef struct _UNSIGNED_RATIO {
    UINT32 uiNumerator;
    UINT32 uiDenominator;
} UNSIGNED_RATIO;

typedef struct _DWM_TIMING_INFO {
    UINT32 cbSize;
    UNSIGNED_RATIO rateRefresh;
    QPC_TIME qpcRefreshPeriod;
    UNSIGNED_RATIO rateCompose;
    QPC_TIME qpcVBlank;
    DWM_FRAME_COUNT cRefresh;
    UINT cDXRefresh;
    QPC_TIME qpcCompose;
    DWM_FRAME_COUNT cFrame;
    UINT cDXPresent;
    DWM_FRAME_COUNT cRefreshFrame;
    DWM_FRAME_COUNT cFrameSubmitted;
    UINT cDXPresentSubmitted;
    DWM_FRAME_COUNT cFrameConfirmed;
    UINT cDXPresentConfirmed;
    DWM_FRAME_COUNT cRefreshConfirmed;
    UINT cDXRefreshConfirmed;
    DWM_FRAME_COUNT cFramesLate;
    UINT cFramesOutstanding;
    DWM_FRAME_COUNT cFrameDisplayed;
    QPC_TIME qpcFrameDisplayed;
    DWM_FRAME_COUNT cRefreshFrameDisplayed;
    DWM_FRAME_COUNT cFrameComplete;
    QPC_TIME qpcFrameComplete;
    DWM_FRAME_COUNT cFramePending;
    QPC_TIME qpcFramePending;
    DWM_FRAME_COUNT cFramesDisplayed;
    DWM_FRAME_COUNT cFramesComplete;
    DWM_FRAME_COUNT cFramesPending;
    DWM_FRAME_COUNT cFramesAvailable;
    DWM_FRAME_COUNT cFramesDropped;
    DWM_FRAME_COUNT cFramesMissed;
    DWM_FRAME_COUNT cRefreshNextDisplayed;
    DWM_FRAME_COUNT cRefreshNextPresented;
    DWM_FRAME_COUNT cRefreshesDisplayed;
    DWM_FRAME_COUNT cRefreshesPresented;
    DWM_FRAME_COUNT cRefreshStarted;
    ULONGLONG cPixelsReceived;
    ULONGLONG cPixelsDrawn;
    DWM_FRAME_COUNT cBuffersEmpty;
} DWM_TIMING_INFO;

typedef enum {
    DWM_SOURCE_FRAME_SAMPLING_POINT,	// Use the first source frame that includes the first refresh of the output frame
    DWM_SOURCE_FRAME_SAMPLING_COVERAGE,	// use the source frame that includes the most refreshes of out the output frame in case of multiple source frames with the same coverage the last will be used
    DWM_SOURCE_FRAME_SAMPLING_LAST		// Sentinel value
} DWM_SOURCE_FRAME_SAMPLING;

/* static const UINT c_DwmMaxQueuedBuffers = 8; */
/* static const UINT c_DwmMaxMonitors = 16; */
/* static const UINT c_DwmMaxAdapters = 16; */

typedef struct _DWM_PRESENT_PARAMETERS {
    UINT32 cbSize;
    BOOL fQueue;
    DWM_FRAME_COUNT cRefreshStart;
    UINT cBuffer;
    BOOL fUseSourceRate;
    UNSIGNED_RATIO rateSource;
    UINT cRefreshesPerFrame;
    DWM_SOURCE_FRAME_SAMPLING eSampling;
} DWM_PRESENT_PARAMETERS;

#ifndef _MIL_MATRIX3X2D_DEFINED
typedef struct _MIL_MATRIX3X2D {
    DOUBLE S_11;
    DOUBLE S_12;
    DOUBLE S_21;
    DOUBLE S_22;
    DOUBLE DX;
    DOUBLE DY;
} MIL_MATRIX3X2D;
#define _MIL_MATRIX3X2D_DEFINED
#endif /* _MIL_MATRIX3X2D_DEFINED */

enum DWMTRANSITION_OWNEDWINDOW_TARGET {
    DWMTRANSITION_OWNEDWINDOW_NULL = -1,
    DWMTRANSITION_OWNEDWINDOW_REPOSITION = 0,
};

#if (NTDDI_VERSION >= NTDDI_WIN8)

enum GESTURE_TYPE {
    GT_PEN_TAP = 0,
    GT_PEN_DOUBLETAP = 1,
    GT_PEN_RIGHTTAP = 2,
    GT_PEN_PRESSANDHOLD = 3,
    GT_PEN_PRESSANDHOLDABORT = 4,
    GT_TOUCH_TAP = 5,
    GT_TOUCH_DOUBLETAP = 6,
    GT_TOUCH_RIGHTTAP = 7,
    GT_TOUCH_PRESSANDHOLD = 8,
    GT_TOUCH_PRESSANDHOLDABORT = 9,
    GT_TOUCH_PRESSANDTAP = 10,
};

enum DWM_SHOWCONTACT {
    DWMSC_DOWN = 0x00000001,
    DWMSC_UP = 0x00000002,
    DWMSC_DRAG = 0x00000004,
    DWMSC_HOLD = 0x00000008,
    DWMSC_PENBARREL = 0x00000010,
    DWMSC_NONE = 0x00000000,
    DWMSC_ALL = 0xFFFFFFFF
};
/* DEFINE_ENUM_FLAG_OPERATORS(DWM_SHOWCONTACT); */

#endif /* NTDDI_VERSION >= NTDDI_WIN8 */

DWMAPI_(BOOL) DwmDefWindowProc(HWND, UINT, WPARAM, LPARAM, LRESULT *);
DWMAPI DwmEnableBlurBehindWindow(HWND, const DWM_BLURBEHIND *);
#if NTDDI_VERSION >= NTDDI_WIN8
__declspec(deprecated) DWMAPI DwmEnableComposition(UINT);
#else /* NTDDI_VERSION < NTDDI_WIN8 */
DWMAPI DwmEnableComposition(UINT);
#endif /* NTDDI_VERSION < NTDDI_WIN8 */
DWMAPI DwmEnableMMCSS(BOOL);
DWMAPI DwmExtendFrameIntoClientArea(HWND, const MARGINS *);
DWMAPI DwmGetColorizationColor(DWORD *, BOOL *);
DWMAPI DwmGetCompositionTimingInfo(HWND, DWM_TIMING_INFO *);
DWMAPI DwmGetWindowAttribute(HWND, DWORD, PVOID, DWORD);
DWMAPI DwmIsCompositionEnabled(BOOL *);
DWMAPI DwmModifyPreviousDxFrameDuration(HWND, INT, BOOL);
DWMAPI DwmQueryThumbnailSourceSize(HTHUMBNAIL, PSIZE);
DWMAPI DwmRegisterThumbnail(HWND, HWND, PHTHUMBNAIL);
DWMAPI DwmSetDxFrameDuration(HWND, INT);
DWMAPI DwmSetPresentParameters(HWND, DWM_PRESENT_PARAMETERS *);
DWMAPI DwmSetWindowAttribute(HWND, DWORD, LPCVOID, DWORD);
DWMAPI DwmUnregisterThumbnail(HTHUMBNAIL);
DWMAPI DwmUpdateThumbnailProperties(HTHUMBNAIL, const DWM_THUMBNAIL_PROPERTIES *);
#if (_WIN32_WINNT >= 0x0601)
#define DWM_SIT_DISPLAYFRAME  0x00000001
DWMAPI DwmSetIconicThumbnail(HWND, HBITMAP, DWORD);
DWMAPI DwmSetIconicLivePreviewBitmap(HWND, HBITMAP, POINT *, DWORD);
DWMAPI DwmInvalidateIconicBitmaps(HWND);
#endif /* _WIN32_WINNT >= 0x0601 */
DWMAPI DwmAttachMilContent(HWND);
DWMAPI DwmDetachMilContent(HWND);
DWMAPI DwmFlush(void);
DWMAPI DwmGetGraphicsStreamTransformHint(UINT, MIL_MATRIX3X2D *);
DWMAPI DwmGetGraphicsStreamClient(UINT, UUID *);
DWMAPI DwmGetTransportAttributes(BOOL *, BOOL *, DWORD *);
DWMAPI DwmTransitionOwnedWindow(HWND, enum DWMTRANSITION_OWNEDWINDOW_TARGET);
#if (NTDDI_VERSION >= NTDDI_WIN8)
DWMAPI DwmRenderGesture(enum GESTURE_TYPE, UINT, const DWORD *, const POINT *);
DWMAPI DwmTetherContact(DWORD, BOOL, POINT);
DWMAPI DwmShowContact(DWORD, enum DWM_SHOWCONTACT);
#endif /* NTDDI_VERSION >= NTDDI_WIN8 */

#if __POCC__ >= 290
#pragma warn(pop)
#endif

#ifdef __cplusplus
}
#endif

#include <poppack.h>

#endif /* _DWMAPI_H */

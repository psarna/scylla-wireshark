#ifndef __WIN32_FILE_DLG_H__
#define __WIN32_FILE_DLG_H__

/** the action to take, after save has been done */
/* XXX - Copied verbatim from gtk/file_dlg.h */
typedef enum {
    after_save_no_action,           /**< no action to take */
    after_save_close_file,          /**< close the file */
    after_save_open_dialog,         /**< open the file open dialog */
    after_save_open_recent_file,    /**< open the specified recent file */
    after_save_open_dnd_file,       /**< open the specified file from drag and drop */
    after_save_merge_dialog,        /**< open the file merge dialog */
    after_save_capture_dialog,      /**< open the capture dialog */
    after_save_exit                 /**< exit program */
} action_after_save_e;


/** Open the "Open" dialog box.
 *
 * @param h_wnd HWND of the parent window.
 */
gboolean win32_open_file (HWND h_wnd);

/** Open the "Save As" dialog box.
 *
 * @param h_wnd HWND of the parent window.
 * @param action_after_save The action to take, when save completed
 * @param action_after_save_data Data for action_after_save
 */
void win32_save_as_file(HWND h_wnd, action_after_save_e action_after_save, gpointer action_after_save_data);

/** Open the "Merge" dialog box.
 *
 * @param h_wnd HWND of the parent window.
 */
void win32_merge_file (HWND h_wnd);

/** Open the "Export" dialog box.
 *
 * @param h_wnd HWND of the parent window.
 */
void win32_export_file (HWND h_wnd);

/** Open the "Export raw bytes" dialog box.
 *
 * @param h_wnd HWND of the parent window.
 */
void win32_export_raw_file (HWND h_wnd);

/** Given a print_args_t struct, update a set of print/export format controls
 *  accordingly.
 *
 * @param dlg_hwnd HWND of the dialog in question.
 * @args Pointer to a print args struct.
 */
/* XXX - This should be moved to win32-print.c, maybe? */
void print_update_dynamic(HWND dlg_hwnd, print_args_t *args); 

/* Open dialog defines */
#define EWFD_FILTER_BTN    1000
#define EWFD_FILTER_EDIT   1001

#define EWFD_MAC_NR_CB     1002
#define EWFD_NET_NR_CB     1003
#define EWFD_TRANS_NR_CB   1004

/* Note: The preview title (PT) and text (PTX) MUST have sequential IDs;
   they're used in a for loop. EWFD_PT_FILENAME MUST be first, and 
   EWFD_PTX_ELAPSED MUST be last.  (so why don't we just use an enum? */
#define EWFD_PT_FILENAME   1005
#define EWFD_PT_FORMAT     1006
#define EWFD_PT_SIZE       1007
#define EWFD_PT_PACKETS    1008
#define EWFD_PT_FIRST_PKT  1009
#define EWFD_PT_ELAPSED    1010

#define EWFD_PTX_FILENAME  1011
#define EWFD_PTX_FORMAT    1012
#define EWFD_PTX_SIZE      1013
#define EWFD_PTX_PACKETS   1014
#define EWFD_PTX_FIRST_PKT 1015
#define EWFD_PTX_ELAPSED   1016


/* Save dialog defines */
#define EWFD_CAPTURED_BTN    1000
#define EWFD_DISPLAYED_BTN   1001
#define EWFD_ALL_PKTS_BTN    1002
#define EWFD_SEL_PKT_BTN     1003
#define EWFD_MARKED_BTN      1004
#define EWFD_FIRST_LAST_BTN  1005
#define EWFD_RANGE_BTN       1006
#define EWFD_RANGE_EDIT      1007
#define EWFD_FILE_TYPE_COMBO 1008

#define EWFD_ALL_PKTS_CAP    1009
#define EWFD_SEL_PKT_CAP     1010
#define EWFD_MARKED_CAP      1011
#define EWFD_FIRST_LAST_CAP  1012
#define EWFD_RANGE_CAP       1013

#define EWFD_ALL_PKTS_DISP   1014
#define EWFD_SEL_PKT_DISP    1015
#define EWFD_MARKED_DISP     1016
#define EWFD_FIRST_LAST_DISP 1017
#define EWFD_RANGE_DISP      1018

/* Export raw dialog defines. */
#define EWFD_EXPORTRAW_ST 1000

/* Merge dialog defines.  Overlays Open dialog defines above. */
#define EWFD_MERGE_PREPEND_BTN 1050
#define EWFD_MERGE_CHRONO_BTN  1051
#define EWFD_MERGE_APPEND_BTN  1052

/* Export dialog defines.  Overlays Save dialog defines above. */
/* These MUST be contiguous */
#define EWFD_PKT_FORMAT_GB    1050
#define EWFD_PKT_SUMMARY_CB   1051
#define EWFD_PKT_DETAIL_CB    1052
#define EWFD_PKT_DETAIL_COMBO 1053
#define EWFD_PKT_BYTES_CB     1054
#define EWFD_PKT_NEW_PAGE_CB  1055

#endif /* win32-file-dlg.h */

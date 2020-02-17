/*******************************************************************************
*   Ledger Blue
*   (c) 2016 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "os.h"
#include "cx.h"
#include "ux.h"

#include <string.h>

#define CLA 0x80
#define INS_SIGN 0x02
#define INS_GET_PUBLIC_KEY 0x04
#define P1_LAST 0x80
#define P1_MORE 0x00

#define MAX_CHARS_PER_LINE 15

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

// if attacker sends only new lines, they are converted to ' | ' so the buffer
// may hold sufficient space to handle them.
static unsigned char to_display[IO_SEPROXYHAL_BUFFER_SIZE_B * 3 + MAX_CHARS_PER_LINE + 1];

static unsigned char *noncestr;
static unsigned char *datetime;

static char lineBuffer[50];

static unsigned int  len_to_display;
static unsigned int  current_text_pos; // parsing cursor in the text to display
static unsigned char isFirstPart;      // if this is the first part of a message
static unsigned char is_last_text_part;
static unsigned char last_part_displayed;

static cx_sha256_t hash;

// UI currently displayed
enum UI_STATE { UI_IDLE, UI_TEXT, UI_APPROVAL };

enum UI_STATE uiState;

ux_state_t ux;

// private key in flash. const and N_ variable name are mandatory here
static const cx_ecfp_private_key_t N_privateKey;
// initialization marker in flash. const and N_ variable name are mandatory here
static const unsigned char N_initialized;

// functions declarations

static const bagl_element_t *io_seproxyhal_touch_exit(const bagl_element_t *e);
static const bagl_element_t *io_seproxyhal_touch_approve(const bagl_element_t *e);
static const bagl_element_t *io_seproxyhal_touch_deny(const bagl_element_t *e);

static void ui_idle(void);
static void ui_text(void);
static void ui_approval(void);

static void request_next_part();
static void on_new_transaction_part(unsigned char *text, unsigned int len);
static void display_text_part(void);

////////////////////////////////////////////////////////////////////////////////

static const bagl_element_t bagl_ui_idle_nanos[] = {
    // {
    //     {type, userid, x, y, width, height, stroke, radius, fill, fgcolor,
    //      bgcolor, font_id, icon_id},
    //     text,
    //     touch_area_brim,
    //     overfgcolor,
    //     overbgcolor,
    //     tap,
    //     out,
    //     over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000,
         0xFFFFFF, 0, 0},
        NULL,
    },
    {
        {BAGL_LABELINE, 0x02, 0, 12, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000,
         BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
        "Waiting for",
    },
    {
        {BAGL_LABELINE, 0x02, 0, 26, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000,
         BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
        "transaction",
    },
    {
        {BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
         BAGL_GLYPH_ICON_CROSS},
        NULL,
    },
};

static unsigned int
bagl_ui_idle_nanos_button(unsigned int button_mask,
                          unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT:
        io_seproxyhal_touch_exit(NULL);
        break;
    }

    return 0;
}

static const bagl_element_t bagl_ui_approval_nanos[] = {
    // {
    //     {type, userid, x, y, width, height, stroke, radius, fill, fgcolor,
    //      bgcolor, font_id, icon_id},
    //     text,
    //     touch_area_brim,
    //     overfgcolor,
    //     overbgcolor,
    //     tap,
    //     out,
    //     over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000,
         0xFFFFFF, 0, 0},
        NULL,
    },
    {
        {BAGL_LABELINE, 0x02, 0, 12, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000,
         BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
        "Sign transaction",
    },
    {
        {BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
         BAGL_GLYPH_ICON_CROSS},
        NULL,
    },
    {
        {BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
         BAGL_GLYPH_ICON_CHECK},
        NULL,
    },
};

static unsigned int
bagl_ui_approval_nanos_button(unsigned int button_mask,
                              unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        io_seproxyhal_touch_approve(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        io_seproxyhal_touch_deny(NULL);
        break;
    }
    return 0;
}

static const bagl_element_t bagl_ui_text_review_nanos[] = {
    // {
    //     {type, userid, x, y, width, height, stroke, radius, fill, fgcolor,
    //      bgcolor, font_id, icon_id},
    //     text,
    //     touch_area_brim,
    //     overfgcolor,
    //     overbgcolor,
    //     tap,
    //     out,
    //     over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000,
         0xFFFFFF, 0, 0},
        NULL,
    },
    {
        {BAGL_LABELINE, 0x02, 0, 12, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000,
         BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
        "SQL Commands",
    },
    {
        {BAGL_LABELINE, 0x02, 20, 26, 88, 11, 0, 0, 0, 0xFFFFFF,
         0x000000, BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
        lineBuffer,
    },
    {
        {BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
         BAGL_GLYPH_ICON_CROSS},
        NULL,
    },
    {
        {BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
         BAGL_GLYPH_ICON_CHECK},
        NULL,
    },
};

static unsigned int
bagl_ui_text_review_nanos_button(unsigned int button_mask,
                                 unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        if (is_last_text_part) {
            ui_approval();
        } else {
            request_next_part();
        }
        break;

    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        io_seproxyhal_touch_deny(NULL);
        break;
    }
    return 0;
}


static const bagl_element_t *io_seproxyhal_touch_exit(const bagl_element_t *e) {
    // Go back to the dashboard
    os_sched_exit(0);
    return NULL; // do not redraw the widget
}

static const bagl_element_t *io_seproxyhal_touch_approve(const bagl_element_t *e) {
    unsigned int tx = 0;

    // Hash is finalized, send back the signature
    unsigned char result[32];
    cx_hash(&hash.header, CX_LAST, G_io_apdu_buffer, 0, result);
    tx = cx_ecdsa_sign((void*) &N_privateKey, CX_RND_RFC6979 | CX_LAST,
                       CX_SHA256, result, sizeof(result), G_io_apdu_buffer, NULL);
    G_io_apdu_buffer[0] &= 0xF0; // discard the parity information

    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;

    // Send back the response and return without waiting for new APDU
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);

    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

static const bagl_element_t *io_seproxyhal_touch_deny(const bagl_element_t *e) {
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response and return without waiting for new APDU
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

static void request_next_part() {
    G_io_apdu_buffer[0] = 0x90;
    G_io_apdu_buffer[1] = 0x00;
    // Send back the response and return without waiting for new APDU
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {

    switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        if (tx_len) {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);
            if (channel & IO_RESET_AFTER_REPLIED) {
                reset();
            }
            return 0; // nothing received from the master so far (it's a tx transaction)
        } else {
            return io_seproxyhal_spi_recv(G_io_apdu_buffer, sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}

static void sample_main(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        volatile unsigned short sw = 0;

        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                // no apdu received, well, reset the session, and reset the
                // bootloader configuration
                if (rx == 0) {
                    THROW(0x6982);
                }

                if (G_io_apdu_buffer[0] != CLA) {
                    THROW(0x6E00);
                }

                switch (G_io_apdu_buffer[1]) {
                case INS_SIGN: {
                    unsigned char *text;
                    unsigned int len, i;
                    if ((G_io_apdu_buffer[2] != P1_MORE) &&
                        (G_io_apdu_buffer[2] != P1_LAST)) {
                        THROW(0x6A86);
                    }
                    // check the message length
                    len = G_io_apdu_buffer[4];
                    if (len > 250) {
                        THROW(0x6700);  //917E
                    }
                    if (G_io_apdu_buffer[2] == P1_MORE && len < 50) {
                        THROW(0x6700);  //917E
                    }
                    // check for nulls in the middle of the message
                    text = G_io_apdu_buffer + 5;
                    for (i=0; i<len; i++) {
                      if (text[i] == '\0') {
                        THROW(0x6984);
                      }
                    }
                    text[len] = '\0';
                    on_new_transaction_part(text, len);
                    flags |= IO_ASYNCH_REPLY;
                } break;

                case INS_GET_PUBLIC_KEY: {
                    cx_ecfp_public_key_t publicKey;
                    cx_ecfp_private_key_t privateKey;
                    os_memmove(&privateKey, &N_privateKey, sizeof(cx_ecfp_private_key_t));
                    cx_ecfp_generate_pair(CX_CURVE_256K1, &publicKey, &privateKey, 1);
                    os_memmove(G_io_apdu_buffer, publicKey.W, 65);
                    tx = 65;
                    THROW(0x9000);
                } break;

                case 0xFF: // return to dashboard
                    goto return_to_dashboard;

                default:
                    THROW(0x6D00);
                    break;
                }
            }
            CATCH_OTHER(e) {
                switch (e & 0xF000) {
                case 0x6000:
                case 0x9000:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
                    break;
                }
                // Unexpected exception => report
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;
            }
            FINALLY {
            }
        }
        END_TRY;
    }

return_to_dashboard:
    return;
}

void io_seproxyhal_display(const bagl_element_t *element) {
    io_seproxyhal_display_default((bagl_element_t *)element);
}

static unsigned char * stripchr(unsigned char *mainstr, int separator) {
  unsigned char *ptr;
  if (mainstr == NULL) return NULL;
  ptr = (unsigned char*) strchr((char*)mainstr, separator);
  if (ptr == 0) return NULL;
  ptr[0] = '\0';
  ptr++;
  return ptr;
}

static void on_new_transaction_part(unsigned char *text, unsigned int len) {
    unsigned int i, dest;

    is_last_text_part = (G_io_apdu_buffer[2] == P1_LAST);

    if (uiState == UI_IDLE || last_part_displayed) {
        isFirstPart = 1;
    } else {
        isFirstPart = 0;
    }
    last_part_displayed = is_last_text_part;

    if (isFirstPart) {
        cx_sha256_init(&hash);
    }
    // Update the hash with this part
    cx_hash(&hash.header, 0, text, len, NULL);

    if (isFirstPart) {
        dest = 0;
    } else {
        memcpy(to_display, &to_display[len_to_display-MAX_CHARS_PER_LINE+1], MAX_CHARS_PER_LINE-1);
        dest = MAX_CHARS_PER_LINE - 1;
    }

    if (isFirstPart) {
        // parse the transaction nonce and datetime
        unsigned char *commands;
        noncestr = text;
        datetime = stripchr(noncestr, '\n');
        commands = stripchr(datetime, '\n');
        if (!commands) {
            THROW(0x6984);  //! can it be here? test
        }
        len -= (commands - text);
        text = commands;
    }

#if 0
    // do not show trailing line breaks
    if (is_last_text_part) {
        for (i=len-1; i>=0; i--) {
            WIDE char c = text[i];
            if (c == '\n' || c == '\r') {
                len--;
            }
        }
    }
#endif

    for (i=0; i<len; i++) {
        unsigned char c = text[i];
        if (c == '\n' || c == '\r') {
            to_display[dest++] = ' ';
            to_display[dest++] = '|';
            to_display[dest++] = ' ';
        // an attacker could use many backspace chars to hide a command
        } else if (c == 0x08) {
            to_display[dest++] = '!';
        } else {
            to_display[dest++] = c;
        }
    }

    len_to_display = dest;
    current_text_pos = 0;
    display_text_part();

    if (isFirstPart) {
        ui_text();
    } else {
        UX_REDISPLAY();
    }

}

static unsigned char text_part_completely_displayed() {
    if (current_text_pos > 0) {
      if (current_text_pos + MAX_CHARS_PER_LINE > len_to_display) {
        return 1;
      }
    }
    return 0;
}

// Pick the text elements to display
static void display_text_part() {
    unsigned int len;
    if (text_part_completely_displayed()) {
        return;
    }
    len = len_to_display - current_text_pos;
    if (len > MAX_CHARS_PER_LINE) {
      len = MAX_CHARS_PER_LINE;
    }
    memcpy(lineBuffer, &to_display[current_text_pos], len);
    lineBuffer[len] = '\0';
    current_text_pos++;
}

static void ui_idle(void) {
    uiState = UI_IDLE;
    UX_DISPLAY(bagl_ui_idle_nanos, NULL);
}

static void ui_text(void) {
    uiState = UI_TEXT;
    UX_DISPLAY(bagl_ui_text_review_nanos, NULL);
}

static void ui_approval(void) {
    uiState = UI_APPROVAL;
    UX_DISPLAY(bagl_ui_approval_nanos, NULL);
}

unsigned char io_event(unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_FINGER_EVENT:
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT: // for Nano S
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        if (UX_DISPLAYED()) {
            // perform action after screen elements have been displayed
            if (uiState == UI_TEXT) {
              if (isFirstPart && current_text_pos <= 1) {
                UX_CALLBACK_SET_INTERVAL(2000);
              } else if (text_part_completely_displayed() && is_last_text_part) {
                UX_CALLBACK_SET_INTERVAL(2000);
              } else {
                UX_CALLBACK_SET_INTERVAL(200);
              }
            }
        } else {
            UX_DISPLAYED_EVENT();
        }
        break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
        UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
          //if (UX_ALLOWED) {
            if (uiState == UI_TEXT) {
                if (text_part_completely_displayed()) {
                    //if (is_last_text_part) {
                    //    ui_approval();
                    //} else {
                        request_next_part();
                    //}
                } else {
                    display_text_part();
                    UX_REDISPLAY();
                }
            }
          //}
        });
        break;

    // unknown events are acknowledged
    default:
        UX_DEFAULT_EVENT();
        break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

__attribute__((section(".boot"))) int main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    current_text_pos = 0;
    uiState = UI_IDLE;

    // ensure exception will work as planned
    os_boot();

    UX_INIT();

    BEGIN_TRY {
        TRY {
            io_seproxyhal_init();

            // Create the private key if not initialized
            if (N_initialized != 0x01) {
                unsigned char canary;
                cx_ecfp_private_key_t privateKey;
                cx_ecfp_public_key_t publicKey;
                cx_ecfp_generate_pair(CX_CURVE_256K1, &publicKey, &privateKey, 0);
                nvm_write((void*) &N_privateKey, &privateKey, sizeof(privateKey));
                canary = 0x01;
                nvm_write((void*) &N_initialized, &canary, sizeof(canary));
            }

#ifdef LISTEN_BLE
            if (os_seph_features() & SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_BLE) {
                BLE_power(0, NULL);
                // restart IOs
                BLE_power(1, NULL);
            }
#endif

            USB_power(0);
            USB_power(1);

            ui_idle();

            sample_main();
        }
        CATCH_OTHER(e) {
        }
        FINALLY {
        }
    }
    END_TRY;
}

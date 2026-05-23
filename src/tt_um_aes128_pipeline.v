// =============================================================================
// tt_um_aes128_pipeline.v
// Tiny Tapeout (GF180) wrapper for AES-128 pipelined encryption core
//
// Pin mapping (Tiny Tapeout standard interface):
//   ui_in  [7:0]  - Dedicated inputs
//   uo_out [7:0]  - Dedicated outputs
//   uio_in [7:0]  - Bidirectional IOs: input path
//   uio_out[7:0]  - Bidirectional IOs: output path
//   uio_oe [7:0]  - Bidirectional IOs: enable (1=output)
//   ena           - Design enable (active high)
//   clk           - Clock
//   rst_n         - Reset (active low)
//
// Serial Protocol (load phase, 32 cycles):
//   Control via ui_in[7:6]:
//     2'b00 = IDLE
//     2'b01 = LOAD   – shift key_in & plain_in one byte per cycle
//     2'b10 = START  – latch loaded data and begin encryption
//     2'b11 = READ   – shift cipher_out out on uo_out[7:0], one byte per cycle
//
//   During LOAD (32 cycles total):
//     Cycles  0-15: ui_in[7:0] shifts into key_in   (MSB first, byte 0 first)
//     Cycles 16-31: ui_in[7:0] shifts into plain_in (MSB first, byte 0 first)
//     uio_in[4:0] carries the byte index (0-31) for load sequencing.
//
//   During START (1 cycle):
//     Latches key_in and plain_in, pulses internal start signal for 1 cycle.
//
//   During READ (16 cycles, after done asserts):
//     uo_out[7:0]   = current output byte (byte index from uio_in[3:0])
//     uio_out[0]    = done signal (pipeline valid output ready)
//     uio_out[1]    = busy (pipeline running)
//
//   Simplified byte-addressed READ:
//     Set uio_in[3:0] to the desired byte index (0-15, MSB-first).
//     uo_out[7:0] will present that byte of cipher_out.
//
// Pipeline latency: 10 clock cycles after START pulse.
// =============================================================================

`timescale 1ns/1ps
`default_nettype none

module tt_um_aes128_pipeline (
    input  wire [7:0] ui_in,    // Dedicated inputs
    output wire [7:0] uo_out,   // Dedicated outputs
    input  wire [7:0] uio_in,   // IOs: Input path
    output wire [7:0] uio_out,  // IOs: Output path
    output wire [7:0] uio_oe,   // IOs: Enable path (active high: 0=input, 1=output)
    input  wire       ena,      // Will go high when the design is enabled
    input  wire       clk,      // Clock
    input  wire       rst_n     // Reset - low to reset
);

    // =========================================================================
    // Control signals decoded from ui_in[7:6]
    // =========================================================================
    localparam CMD_IDLE  = 2'b00;
    localparam CMD_LOAD  = 2'b01;
    localparam CMD_START = 2'b10;
    localparam CMD_READ  = 2'b11;

    wire [1:0] cmd      = ui_in[7:6];
    wire [7:0] data_in  = ui_in[7:0];  // full byte for LOAD
    wire [3:0] rd_idx   = uio_in[3:0]; // byte index for READ (0-15)
    wire [4:0] ld_idx   = uio_in[4:0]; // byte index for LOAD  (0-31)

    // =========================================================================
    // Input shift registers: key (128-bit) and plaintext (128-bit)
    // =========================================================================
    reg [127:0] key_reg;
    reg [127:0] plain_reg;

    always @(posedge clk) begin
        if (!rst_n) begin
            key_reg   <= 128'b0;
            plain_reg <= 128'b0;
        end else if (ena && cmd == CMD_LOAD) begin
            // Each cycle during LOAD, write one byte at the specified index.
            // ld_idx 0-15  -> key_reg   byte (0 = MSB)
            // ld_idx 16-31 -> plain_reg byte (0 = MSB)
            if (ld_idx <= 5'd15) begin
                // key byte: index 0 maps to bits [127:120], etc.
                case (ld_idx[3:0])
                    4'd0:  key_reg[127:120] <= ui_in;
                    4'd1:  key_reg[119:112] <= ui_in;
                    4'd2:  key_reg[111:104] <= ui_in;
                    4'd3:  key_reg[103: 96] <= ui_in;
                    4'd4:  key_reg[ 95: 88] <= ui_in;
                    4'd5:  key_reg[ 87: 80] <= ui_in;
                    4'd6:  key_reg[ 79: 72] <= ui_in;
                    4'd7:  key_reg[ 71: 64] <= ui_in;
                    4'd8:  key_reg[ 63: 56] <= ui_in;
                    4'd9:  key_reg[ 55: 48] <= ui_in;
                    4'd10: key_reg[ 47: 40] <= ui_in;
                    4'd11: key_reg[ 39: 32] <= ui_in;
                    4'd12: key_reg[ 31: 24] <= ui_in;
                    4'd13: key_reg[ 23: 16] <= ui_in;
                    4'd14: key_reg[ 15:  8] <= ui_in;
                    4'd15: key_reg[  7:  0] <= ui_in;
                endcase
            end else begin
                // plaintext byte: ld_idx 16 -> byte 0 (MSB)
                case (ld_idx[3:0])
                    4'd0:  plain_reg[127:120] <= ui_in;
                    4'd1:  plain_reg[119:112] <= ui_in;
                    4'd2:  plain_reg[111:104] <= ui_in;
                    4'd3:  plain_reg[103: 96] <= ui_in;
                    4'd4:  plain_reg[ 95: 88] <= ui_in;
                    4'd5:  plain_reg[ 87: 80] <= ui_in;
                    4'd6:  plain_reg[ 79: 72] <= ui_in;
                    4'd7:  plain_reg[ 71: 64] <= ui_in;
                    4'd8:  plain_reg[ 63: 56] <= ui_in;
                    4'd9:  plain_reg[ 55: 48] <= ui_in;
                    4'd10: plain_reg[ 47: 40] <= ui_in;
                    4'd11: plain_reg[ 39: 32] <= ui_in;
                    4'd12: plain_reg[ 31: 24] <= ui_in;
                    4'd13: plain_reg[ 23: 16] <= ui_in;
                    4'd14: plain_reg[ 15:  8] <= ui_in;
                    4'd15: plain_reg[  7:  0] <= ui_in;
                endcase
            end
        end
    end

    // =========================================================================
    // START pulse: one-cycle strobe when cmd == CMD_START
    // =========================================================================
    reg start_reg;

    always @(posedge clk) begin
        if (!rst_n)
            start_reg <= 1'b0;
        else
            start_reg <= (ena && cmd == CMD_START) ? 1'b1 : 1'b0;
    end

    // =========================================================================
    // AES pipeline core instantiation
    // =========================================================================
    wire        done;
    wire [127:0] cipher_out;

    aes_pipeline_top u_aes (
        .clk        (clk),
        .rst_n      (rst_n),
        .start      (start_reg),
        .key_in     (key_reg),
        .plain_in   (plain_reg),
        .done       (done),
        .cipher_out (cipher_out)
    );

    // =========================================================================
    // Output byte mux: select byte from cipher_out using rd_idx
    // =========================================================================
    reg [7:0] out_byte;

    always @(*) begin
        case (rd_idx)
            4'd0:  out_byte = cipher_out[127:120];
            4'd1:  out_byte = cipher_out[119:112];
            4'd2:  out_byte = cipher_out[111:104];
            4'd3:  out_byte = cipher_out[103: 96];
            4'd4:  out_byte = cipher_out[ 95: 88];
            4'd5:  out_byte = cipher_out[ 87: 80];
            4'd6:  out_byte = cipher_out[ 79: 72];
            4'd7:  out_byte = cipher_out[ 71: 64];
            4'd8:  out_byte = cipher_out[ 63: 56];
            4'd9:  out_byte = cipher_out[ 55: 48];
            4'd10: out_byte = cipher_out[ 47: 40];
            4'd11: out_byte = cipher_out[ 39: 32];
            4'd12: out_byte = cipher_out[ 31: 24];
            4'd13: out_byte = cipher_out[ 23: 16];
            4'd14: out_byte = cipher_out[ 15:  8];
            4'd15: out_byte = cipher_out[  7:  0];
            default: out_byte = 8'b0;
        endcase
    end

    // =========================================================================
    // Output assignments
    // =========================================================================

    // uo_out: cipher byte during READ, otherwise status
    assign uo_out = (cmd == CMD_READ) ? out_byte :
                    {6'b0, start_reg, done};

    // uio: outputs driven; uio_out[0] = done, uio_out[1] = start/busy
    assign uio_out = {6'b0, start_reg, done};
    assign uio_oe  = 8'hFF;  // all bidir pins are outputs

    // Unused input: suppress lint warnings
    wire _unused = &{uio_in[7:5], data_in[5:0], 1'b0};

endmodule


// =============================================================================
// All supporting modules included below (from aes_pipeline_top.v and helpers)
// =============================================================================

// ---------- aes_pipeline_top (verbatim from project) ------------------------

`timescale 1ns/1ps

module aes_pipeline_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,

    input  wire [127:0] key_in,
    input  wire [127:0] plain_in,

    output wire         done,
    output wire [127:0] cipher_out
);

    wire [1407:0] all_round_keys;
    wire [127:0] round_key [0:10];

    key_gen u_key_gen (
        .key_in        (key_in),
        .round_key_out (all_round_keys)
    );

    genvar rk;
    generate
        for (rk = 0; rk <= 10; rk = rk + 1) begin : RK_UNPACK
            assign round_key[rk] = all_round_keys[(10-rk)*128 +: 128];
        end
    endgenerate

    wire [127:0] init_state;
    assign init_state = plain_in ^ round_key[0];

    reg [127:0] stage0, stage1, stage2, stage3, stage4;
    reg [127:0] stage5, stage6, stage7, stage8, stage9, stage10;

    wire [127:0] round1_out, round2_out, round3_out, round4_out, round5_out;
    wire [127:0] round6_out, round7_out, round8_out, round9_out, round10_out;

    aes_round r1  (.state_in(stage0),  .round_key(round_key[1]),  .state_out(round1_out));
    aes_round r2  (.state_in(stage1),  .round_key(round_key[2]),  .state_out(round2_out));
    aes_round r3  (.state_in(stage2),  .round_key(round_key[3]),  .state_out(round3_out));
    aes_round r4  (.state_in(stage3),  .round_key(round_key[4]),  .state_out(round4_out));
    aes_round r5  (.state_in(stage4),  .round_key(round_key[5]),  .state_out(round5_out));
    aes_round r6  (.state_in(stage5),  .round_key(round_key[6]),  .state_out(round6_out));
    aes_round r7  (.state_in(stage6),  .round_key(round_key[7]),  .state_out(round7_out));
    aes_round r8  (.state_in(stage7),  .round_key(round_key[8]),  .state_out(round8_out));
    aes_round r9  (.state_in(stage8),  .round_key(round_key[9]),  .state_out(round9_out));

    aes_final_round r10 (.state_in(stage9), .round_key(round_key[10]), .state_out(round10_out));

    always @(posedge clk) begin
        if (!rst_n) begin
            stage0  <= 128'b0; stage1  <= 128'b0; stage2  <= 128'b0;
            stage3  <= 128'b0; stage4  <= 128'b0; stage5  <= 128'b0;
            stage6  <= 128'b0; stage7  <= 128'b0; stage8  <= 128'b0;
            stage9  <= 128'b0; stage10 <= 128'b0;
        end else begin
            stage0  <= init_state;
            stage1  <= round1_out;  stage2  <= round2_out;
            stage3  <= round3_out;  stage4  <= round4_out;
            stage5  <= round5_out;  stage6  <= round6_out;
            stage7  <= round7_out;  stage8  <= round8_out;
            stage9  <= round9_out;  stage10 <= round10_out;
        end
    end

    reg [10:0] valid_pipe;
    always @(posedge clk) begin
        if (!rst_n)
            valid_pipe <= 11'b0;
        else begin
            valid_pipe[0]  <= start;
            valid_pipe[1]  <= valid_pipe[0];  valid_pipe[2]  <= valid_pipe[1];
            valid_pipe[3]  <= valid_pipe[2];  valid_pipe[4]  <= valid_pipe[3];
            valid_pipe[5]  <= valid_pipe[4];  valid_pipe[6]  <= valid_pipe[5];
            valid_pipe[7]  <= valid_pipe[6];  valid_pipe[8]  <= valid_pipe[7];
            valid_pipe[9]  <= valid_pipe[8];  valid_pipe[10] <= valid_pipe[9];
        end
    end

    assign done       = valid_pipe[10];
    assign cipher_out = stage10;

endmodule


// ---------- aes_round -------------------------------------------------------

module aes_round (
    input  wire [127:0] state_in,
    input  wire [127:0] round_key,
    output wire [127:0] state_out
);
    wire [127:0] sb_out, sr_out, mc_out;
    sub_byte  u_sb (.data_in(state_in), .data_out(sb_out));
    shift_row u_sr (.data_in(sb_out),   .data_out(sr_out));
    mix_col   u_mc (.data_in(sr_out),   .data_out(mc_out));
    assign state_out = mc_out ^ round_key;
endmodule


// ---------- aes_final_round -------------------------------------------------

module aes_final_round (
    input  wire [127:0] state_in,
    input  wire [127:0] round_key,
    output wire [127:0] state_out
);
    wire [127:0] sb_out, sr_out;
    sub_byte  u_sb (.data_in(state_in), .data_out(sb_out));
    shift_row u_sr (.data_in(sb_out),   .data_out(sr_out));
    assign state_out = sr_out ^ round_key;
endmodule


// ---------- key_gen ---------------------------------------------------------

module key_gen (
    input  wire [127:0]  key_in,
    output wire [1407:0] round_key_out
);
    wire [31:0] W [0:43];

    assign W[0] = key_in[127:96];
    assign W[1] = key_in[95:64];
    assign W[2] = key_in[63:32];
    assign W[3] = key_in[31:0];

    // Rcon[1..10]
    wire [7:0] RCON [1:10];
    assign RCON[1]  = 8'h01; assign RCON[2]  = 8'h02;
    assign RCON[3]  = 8'h04; assign RCON[4]  = 8'h08;
    assign RCON[5]  = 8'h10; assign RCON[6]  = 8'h20;
    assign RCON[7]  = 8'h40; assign RCON[8]  = 8'h80;
    assign RCON[9]  = 8'h1b; assign RCON[10] = 8'h36;

    // SubWord helper function — inline via generate
    // W[i] = W[i-4] ^ SubWord(RotWord(W[i-1])) ^ Rcon  (i mod 4 == 0)
    // W[i] = W[i-4] ^ W[i-1]                           (otherwise)

    genvar i;
    generate
        for (i = 4; i <= 43; i = i + 1) begin : KEY_SCHED
            if (i % 4 == 0) begin
                wire [7:0] r0, r1, r2, r3;
                wire [7:0] s0, s1, s2, s3;
                // RotWord: rotate left by 1 byte
                assign r0 = W[i-1][23:16];
                assign r1 = W[i-1][15:8];
                assign r2 = W[i-1][7:0];
                assign r3 = W[i-1][31:24];
                // SubWord
                sbox sb0 (.in_byte(r0), .out_byte(s0));
                sbox sb1 (.in_byte(r1), .out_byte(s1));
                sbox sb2 (.in_byte(r2), .out_byte(s2));
                sbox sb3 (.in_byte(r3), .out_byte(s3));
                assign W[i] = W[i-4] ^ {s0 ^ RCON[i/4], s1, s2, s3};
            end else begin
                assign W[i] = W[i-4] ^ W[i-1];
            end
        end
    endgenerate

    // Pack round keys: RoundKey[k] = {W[4k], W[4k+1], W[4k+2], W[4k+3]}
    // round_key_out[1407:1280] = RK0, ..., round_key_out[127:0] = RK10
    genvar k;
    generate
        for (k = 0; k <= 10; k = k + 1) begin : RK_PACK
            assign round_key_out[(10-k)*128 +: 128] =
                {W[4*k], W[4*k+1], W[4*k+2], W[4*k+3]};
        end
    endgenerate

endmodule


// ---------- sub_byte --------------------------------------------------------

module sub_byte (
    input  wire [127:0] data_in,
    output wire [127:0] data_out
);
    genvar i;
    generate
        for (i = 0; i < 16; i = i + 1) begin : SBOX_INST
            sbox u_sbox (
                .in_byte  (data_in [127 - i*8 -: 8]),
                .out_byte (data_out[127 - i*8 -: 8])
            );
        end
    endgenerate
endmodule


// ---------- shift_row -------------------------------------------------------

module shift_row (
    input  wire [127:0] data_in,
    output wire [127:0] data_out
);
    // Column-major layout: col0=bits[127:96], col1=bits[95:64],
    //                      col2=bits[63:32],  col3=bits[31:0]
    wire [7:0] b00 = data_in[127:120]; wire [7:0] b01 = data_in[95:88];
    wire [7:0] b02 = data_in[63:56];   wire [7:0] b03 = data_in[31:24];
    wire [7:0] b10 = data_in[119:112]; wire [7:0] b11 = data_in[87:80];
    wire [7:0] b12 = data_in[55:48];   wire [7:0] b13 = data_in[23:16];
    wire [7:0] b20 = data_in[111:104]; wire [7:0] b21 = data_in[79:72];
    wire [7:0] b22 = data_in[47:40];   wire [7:0] b23 = data_in[15:8];
    wire [7:0] b30 = data_in[103:96];  wire [7:0] b31 = data_in[71:64];
    wire [7:0] b32 = data_in[39:32];   wire [7:0] b33 = data_in[7:0];

    // Row 0: no shift
    // Row 1: left-shift by 1 (b10->col1, b11->col2, b12->col3, b13->col0)
    // Row 2: left-shift by 2 (b20->col2, b21->col3, b22->col0, b23->col1)
    // Row 3: left-shift by 3 (b30->col3, b31->col0, b32->col1, b33->col2)
    assign data_out[127:120] = b00; assign data_out[95:88]  = b01;
    assign data_out[63:56]   = b02; assign data_out[31:24]  = b03;
    assign data_out[119:112] = b11; assign data_out[87:80]  = b12;
    assign data_out[55:48]   = b13; assign data_out[23:16]  = b10;
    assign data_out[111:104] = b22; assign data_out[79:72]  = b23;
    assign data_out[47:40]   = b20; assign data_out[15:8]   = b21;
    assign data_out[103:96]  = b33; assign data_out[71:64]  = b30;
    assign data_out[39:32]   = b31; assign data_out[7:0]    = b32;
endmodule


// ---------- mix_col ---------------------------------------------------------

module mix_col (
    input  wire [127:0] data_in,
    output wire [127:0] data_out
);
    mixcolumns_one_column u_col0 (.col_in(data_in[127:96]), .col_out(data_out[127:96]));
    mixcolumns_one_column u_col1 (.col_in(data_in[95:64]),  .col_out(data_out[95:64]));
    mixcolumns_one_column u_col2 (.col_in(data_in[63:32]),  .col_out(data_out[63:32]));
    mixcolumns_one_column u_col3 (.col_in(data_in[31:0]),   .col_out(data_out[31:0]));
endmodule

module mixcolumns_one_column (
    input  wire [31:0] col_in,
    output wire [31:0] col_out
);
    wire [7:0] s0 = col_in[31:24];
    wire [7:0] s1 = col_in[23:16];
    wire [7:0] s2 = col_in[15:8];
    wire [7:0] s3 = col_in[7:0];

    // GF(2^8) multiply-by-2 with reduction polynomial x^8 + x^4 + x^3 + x + 1
    function [7:0] xtime;
        input [7:0] b;
        begin
            xtime = (b[7]) ? ((b << 1) ^ 8'h1b) : (b << 1);
        end
    endfunction

    wire [7:0] x2s0 = xtime(s0); wire [7:0] x2s1 = xtime(s1);
    wire [7:0] x2s2 = xtime(s2); wire [7:0] x2s3 = xtime(s3);

    // MixColumns: output = MDS * [s0,s1,s2,s3]^T over GF(2^8)
    assign col_out[31:24] = x2s0 ^ (x2s1 ^ s1) ^ s2 ^ s3;
    assign col_out[23:16] = s0 ^ x2s1 ^ (x2s2 ^ s2) ^ s3;
    assign col_out[15:8]  = s0 ^ s1 ^ x2s2 ^ (x2s3 ^ s3);
    assign col_out[7:0]   = (x2s0 ^ s0) ^ s1 ^ s2 ^ x2s3;
endmodule


// ---------- sbox (AES forward S-box, full 256-entry LUT) --------------------

module sbox (
    input  wire [7:0] in_byte,
    output reg  [7:0] out_byte
);
    always @(*) begin
        case (in_byte)
            8'h00: out_byte = 8'h63; 8'h01: out_byte = 8'h7c;
            8'h02: out_byte = 8'h77; 8'h03: out_byte = 8'h7b;
            8'h04: out_byte = 8'hf2; 8'h05: out_byte = 8'h6b;
            8'h06: out_byte = 8'h6f; 8'h07: out_byte = 8'hc5;
            8'h08: out_byte = 8'h30; 8'h09: out_byte = 8'h01;
            8'h0a: out_byte = 8'h67; 8'h0b: out_byte = 8'h2b;
            8'h0c: out_byte = 8'hfe; 8'h0d: out_byte = 8'hd7;
            8'h0e: out_byte = 8'hab; 8'h0f: out_byte = 8'h76;
            8'h10: out_byte = 8'hca; 8'h11: out_byte = 8'h82;
            8'h12: out_byte = 8'hc9; 8'h13: out_byte = 8'h7d;
            8'h14: out_byte = 8'hfa; 8'h15: out_byte = 8'h59;
            8'h16: out_byte = 8'h47; 8'h17: out_byte = 8'hf0;
            8'h18: out_byte = 8'had; 8'h19: out_byte = 8'hd4;
            8'h1a: out_byte = 8'ha2; 8'h1b: out_byte = 8'haf;
            8'h1c: out_byte = 8'h9c; 8'h1d: out_byte = 8'ha4;
            8'h1e: out_byte = 8'h72; 8'h1f: out_byte = 8'hc0;
            8'h20: out_byte = 8'hb7; 8'h21: out_byte = 8'hfd;
            8'h22: out_byte = 8'h93; 8'h23: out_byte = 8'h26;
            8'h24: out_byte = 8'h36; 8'h25: out_byte = 8'h3f;
            8'h26: out_byte = 8'hf7; 8'h27: out_byte = 8'hcc;
            8'h28: out_byte = 8'h34; 8'h29: out_byte = 8'ha5;
            8'h2a: out_byte = 8'he5; 8'h2b: out_byte = 8'hf1;
            8'h2c: out_byte = 8'h71; 8'h2d: out_byte = 8'hd8;
            8'h2e: out_byte = 8'h31; 8'h2f: out_byte = 8'h15;
            8'h30: out_byte = 8'h04; 8'h31: out_byte = 8'hc7;
            8'h32: out_byte = 8'h23; 8'h33: out_byte = 8'hc3;
            8'h34: out_byte = 8'h18; 8'h35: out_byte = 8'h96;
            8'h36: out_byte = 8'h05; 8'h37: out_byte = 8'h9a;
            8'h38: out_byte = 8'h07; 8'h39: out_byte = 8'h12;
            8'h3a: out_byte = 8'h80; 8'h3b: out_byte = 8'he2;
            8'h3c: out_byte = 8'heb; 8'h3d: out_byte = 8'h27;
            8'h3e: out_byte = 8'hb2; 8'h3f: out_byte = 8'h75;
            8'h40: out_byte = 8'h09; 8'h41: out_byte = 8'h83;
            8'h42: out_byte = 8'h2c; 8'h43: out_byte = 8'h1a;
            8'h44: out_byte = 8'h1b; 8'h45: out_byte = 8'h6e;
            8'h46: out_byte = 8'h5a; 8'h47: out_byte = 8'ha0;
            8'h48: out_byte = 8'h52; 8'h49: out_byte = 8'h3b;
            8'h4a: out_byte = 8'hd6; 8'h4b: out_byte = 8'hb3;
            8'h4c: out_byte = 8'h29; 8'h4d: out_byte = 8'he3;
            8'h4e: out_byte = 8'h2f; 8'h4f: out_byte = 8'h84;
            8'h50: out_byte = 8'h53; 8'h51: out_byte = 8'hd1;
            8'h52: out_byte = 8'h00; 8'h53: out_byte = 8'hed;
            8'h54: out_byte = 8'h20; 8'h55: out_byte = 8'hfc;
            8'h56: out_byte = 8'hb1; 8'h57: out_byte = 8'h5b;
            8'h58: out_byte = 8'h6a; 8'h59: out_byte = 8'hcb;
            8'h5a: out_byte = 8'hbe; 8'h5b: out_byte = 8'h39;
            8'h5c: out_byte = 8'h4a; 8'h5d: out_byte = 8'h4c;
            8'h5e: out_byte = 8'h58; 8'h5f: out_byte = 8'hcf;
            8'h60: out_byte = 8'hd0; 8'h61: out_byte = 8'hef;
            8'h62: out_byte = 8'haa; 8'h63: out_byte = 8'hfb;
            8'h64: out_byte = 8'h43; 8'h65: out_byte = 8'h4d;
            8'h66: out_byte = 8'h33; 8'h67: out_byte = 8'h85;
            8'h68: out_byte = 8'h45; 8'h69: out_byte = 8'hf9;
            8'h6a: out_byte = 8'h02; 8'h6b: out_byte = 8'h7f;
            8'h6c: out_byte = 8'h50; 8'h6d: out_byte = 8'h3c;
            8'h6e: out_byte = 8'h9f; 8'h6f: out_byte = 8'ha8;
            8'h70: out_byte = 8'h51; 8'h71: out_byte = 8'ha3;
            8'h72: out_byte = 8'h40; 8'h73: out_byte = 8'h8f;
            8'h74: out_byte = 8'h92; 8'h75: out_byte = 8'h9d;
            8'h76: out_byte = 8'h38; 8'h77: out_byte = 8'hf5;
            8'h78: out_byte = 8'hbc; 8'h79: out_byte = 8'hb6;
            8'h7a: out_byte = 8'hda; 8'h7b: out_byte = 8'h21;
            8'h7c: out_byte = 8'h10; 8'h7d: out_byte = 8'hff;
            8'h7e: out_byte = 8'hf3; 8'h7f: out_byte = 8'hd2;
            8'h80: out_byte = 8'hcd; 8'h81: out_byte = 8'h0c;
            8'h82: out_byte = 8'h13; 8'h83: out_byte = 8'hec;
            8'h84: out_byte = 8'h5f; 8'h85: out_byte = 8'h97;
            8'h86: out_byte = 8'h44; 8'h87: out_byte = 8'h17;
            8'h88: out_byte = 8'hc4; 8'h89: out_byte = 8'ha7;
            8'h8a: out_byte = 8'h7e; 8'h8b: out_byte = 8'h3d;
            8'h8c: out_byte = 8'h64; 8'h8d: out_byte = 8'h5d;
            8'h8e: out_byte = 8'h19; 8'h8f: out_byte = 8'h73;
            8'h90: out_byte = 8'h60; 8'h91: out_byte = 8'h81;
            8'h92: out_byte = 8'h4f; 8'h93: out_byte = 8'hdc;
            8'h94: out_byte = 8'h22; 8'h95: out_byte = 8'h2a;
            8'h96: out_byte = 8'h90; 8'h97: out_byte = 8'h88;
            8'h98: out_byte = 8'h46; 8'h99: out_byte = 8'hee;
            8'h9a: out_byte = 8'hb8; 8'h9b: out_byte = 8'h14;
            8'h9c: out_byte = 8'hde; 8'h9d: out_byte = 8'h5e;
            8'h9e: out_byte = 8'h0b; 8'h9f: out_byte = 8'hdb;
            8'ha0: out_byte = 8'he0; 8'ha1: out_byte = 8'h32;
            8'ha2: out_byte = 8'h3a; 8'ha3: out_byte = 8'h0a;
            8'ha4: out_byte = 8'h49; 8'ha5: out_byte = 8'h06;
            8'ha6: out_byte = 8'h24; 8'ha7: out_byte = 8'h5c;
            8'ha8: out_byte = 8'hc2; 8'ha9: out_byte = 8'hd3;
            8'haa: out_byte = 8'hac; 8'hab: out_byte = 8'h62;
            8'hac: out_byte = 8'h91; 8'had: out_byte = 8'h95;
            8'hae: out_byte = 8'he4; 8'haf: out_byte = 8'h79;
            8'hb0: out_byte = 8'he7; 8'hb1: out_byte = 8'hc8;
            8'hb2: out_byte = 8'h37; 8'hb3: out_byte = 8'h6d;
            8'hb4: out_byte = 8'h8d; 8'hb5: out_byte = 8'hd5;
            8'hb6: out_byte = 8'h4e; 8'hb7: out_byte = 8'ha9;
            8'hb8: out_byte = 8'h6c; 8'hb9: out_byte = 8'h56;
            8'hba: out_byte = 8'hf4; 8'hbb: out_byte = 8'hea;
            8'hbc: out_byte = 8'h65; 8'hbd: out_byte = 8'h7a;
            8'hbe: out_byte = 8'hae; 8'hbf: out_byte = 8'h08;
            8'hc0: out_byte = 8'hba; 8'hc1: out_byte = 8'h78;
            8'hc2: out_byte = 8'h25; 8'hc3: out_byte = 8'h2e;
            8'hc4: out_byte = 8'h1c; 8'hc5: out_byte = 8'ha6;
            8'hc6: out_byte = 8'hb4; 8'hc7: out_byte = 8'hc6;
            8'hc8: out_byte = 8'he8; 8'hc9: out_byte = 8'hdd;
            8'hca: out_byte = 8'h74; 8'hcb: out_byte = 8'h1f;
            8'hcc: out_byte = 8'h4b; 8'hcd: out_byte = 8'hbd;
            8'hce: out_byte = 8'h8b; 8'hcf: out_byte = 8'h8a;
            8'hd0: out_byte = 8'h70; 8'hd1: out_byte = 8'h3e;
            8'hd2: out_byte = 8'hb5; 8'hd3: out_byte = 8'h66;
            8'hd4: out_byte = 8'h48; 8'hd5: out_byte = 8'h03;
            8'hd6: out_byte = 8'hf6; 8'hd7: out_byte = 8'h0e;
            8'hd8: out_byte = 8'h61; 8'hd9: out_byte = 8'h35;
            8'hda: out_byte = 8'h57; 8'hdb: out_byte = 8'hb9;
            8'hdc: out_byte = 8'h86; 8'hdd: out_byte = 8'hc1;
            8'hde: out_byte = 8'h1d; 8'hdf: out_byte = 8'h9e;
            8'he0: out_byte = 8'he1; 8'he1: out_byte = 8'hf8;
            8'he2: out_byte = 8'h98; 8'he3: out_byte = 8'h11;
            8'he4: out_byte = 8'h69; 8'he5: out_byte = 8'hd9;
            8'he6: out_byte = 8'h8e; 8'he7: out_byte = 8'h94;
            8'he8: out_byte = 8'h9b; 8'he9: out_byte = 8'h1e;
            8'hea: out_byte = 8'h87; 8'heb: out_byte = 8'he9;
            8'hec: out_byte = 8'hce; 8'hed: out_byte = 8'h55;
            8'hee: out_byte = 8'h28; 8'hef: out_byte = 8'hdf;
            8'hf0: out_byte = 8'h8c; 8'hf1: out_byte = 8'ha1;
            8'hf2: out_byte = 8'h89; 8'hf3: out_byte = 8'h0d;
            8'hf4: out_byte = 8'hbf; 8'hf5: out_byte = 8'he6;
            8'hf6: out_byte = 8'h42; 8'hf7: out_byte = 8'h68;
            8'hf8: out_byte = 8'h41; 8'hf9: out_byte = 8'h99;
            8'hfa: out_byte = 8'h2d; 8'hfb: out_byte = 8'h0f;
            8'hfc: out_byte = 8'hb0; 8'hfd: out_byte = 8'h54;
            8'hfe: out_byte = 8'hbb; 8'hff: out_byte = 8'h16;
            default: out_byte = 8'h00;
        endcase
    end
endmodule

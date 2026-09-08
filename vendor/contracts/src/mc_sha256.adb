-- SPDX-License-Identifier: MIT
with Interfaces; with MC_Codec;
package body MC_SHA256 with SPARK_Mode is
   use type Word; use type Wide;
   K : constant Words (0 .. 63) :=
     (16#428A2F98#,16#71374491#,16#B5C0FBCF#,16#E9B5DBA5#,
      16#3956C25B#,16#59F111F1#,16#923F82A4#,16#AB1C5ED5#,
      16#D807AA98#,16#12835B01#,16#243185BE#,16#550C7DC3#,
      16#72BE5D74#,16#80DEB1FE#,16#9BDC06A7#,16#C19BF174#,
      16#E49B69C1#,16#EFBE4786#,16#0FC19DC6#,16#240CA1CC#,
      16#2DE92C6F#,16#4A7484AA#,16#5CB0A9DC#,16#76F988DA#,
      16#983E5152#,16#A831C66D#,16#B00327C8#,16#BF597FC7#,
      16#C6E00BF3#,16#D5A79147#,16#06CA6351#,16#14292967#,
      16#27B70A85#,16#2E1B2138#,16#4D2C6DFC#,16#53380D13#,
      16#650A7354#,16#766A0ABB#,16#81C2C92E#,16#92722C85#,
      16#A2BFE8A1#,16#A81A664B#,16#C24B8B70#,16#C76C51A3#,
      16#D192E819#,16#D6990624#,16#F40E3585#,16#106AA070#,
      16#19A4C116#,16#1E376C08#,16#2748774C#,16#34B0BCB5#,
      16#391C0CB3#,16#4ED8AA4A#,16#5B9CCA4F#,16#682E6FF3#,
      16#748F82EE#,16#78A5636F#,16#84C87814#,16#8CC70208#,
      16#90BEFFFA#,16#A4506CEB#,16#BEF9A3F7#,16#C67178F2#);
   function R (X : Word; N : Natural) return Word is
     (Interfaces.Rotate_Right (X, N));
   procedure Compress (C : in out Context) with Global => null,
     Post => C.Total=C.Total'Old and then C.Used=C.Used'Old
       and then C.Block_Data=C.Block_Data'Old
   is
      W : Words (0 .. 63) := (others => 0);
      A,B,D,E,F,G,H,I : Word;
      S0,S1,T1,T2 : Word;
   begin
      for J in 0 .. 15 loop
         W (J) := MC_Codec.U32 (C.Block_Data, 1 + J * 4);
      end loop;
      for J in 16 .. 63 loop
         S0 := R (W (J - 15), 7) xor R (W (J - 15), 18)
           xor Interfaces.Shift_Right (W (J - 15), 3);
         S1 := R (W (J - 2), 17) xor R (W (J - 2), 19)
           xor Interfaces.Shift_Right (W (J - 2), 10);
         W (J) := W (J - 16) + S0 + W (J - 7) + S1;
      end loop;
      A:=C.State(0); B:=C.State(1); D:=C.State(2); E:=C.State(3);
      F:=C.State(4); G:=C.State(5); H:=C.State(6); I:=C.State(7);
      for J in 0 .. 63 loop
         S1 := R (F, 6) xor R (F, 11) xor R (F, 25);
         T1 := I + S1 + ((F and G) xor ((not F) and H)) + K (J) + W (J);
         S0 := R (A, 2) xor R (A, 13) xor R (A, 22);
         T2 := S0 + ((A and B) xor (A and D) xor (B and D));
         I:=H; H:=G; G:=F; F:=E+T1; E:=D; D:=B; B:=A; A:=T1+T2;
      end loop;
      C.State (0):=C.State(0)+A; C.State(1):=C.State(1)+B;
      C.State (2):=C.State(2)+D; C.State(3):=C.State(3)+E;
      C.State (4):=C.State(4)+F; C.State(5):=C.State(5)+G;
      C.State (6):=C.State(6)+H; C.State(7):=C.State(7)+I;
   end Compress;
   function Initialize return Context is (Context'(others => <>));
   function Length (C : Context) return Wide is (C.Total);
   procedure Update (C : in out Context; Data : Bytes) is
   begin
      for J in Data'Range loop
         C.Block_Data (C.Used + 1) := Data(J);
         C.Total := C.Total + 1;
         if C.Used = 63 then
            Compress (C);
            C.Used := 0;
         else
            C.Used := C.Used + 1;
         end if;
         pragma Loop_Invariant(C.Total=C.Total'Loop_Entry+Wide(J-Data'First+1));
      end loop;
   end Update;
   function Finish (C : Context) return Digest is
      Work : Context := C;
      Padding : Bytes (1 .. 128) := (others => 0);
      Pad_Length : Positive;
      Result : Digest := (others => 0);
   begin
      if Work.Used < 56 then
         Pad_Length := 64 - Work.Used;
      else
         Pad_Length := 128 - Work.Used;
      end if;
      Padding (1) := 16#80#;
      MC_Codec.Put64 (Padding, Pad_Length - 7, C.Total * 8);
      Update (Work, Padding (1 .. Pad_Length));
      for J in 0 .. 7 loop
         MC_Codec.Put32 (Result, 1 + 4 * J, Work.State (J));
      end loop;
      return Result;
   end Finish;
   function Hash (Data : Bytes) return Digest is
      C : Context := Initialize;
   begin
      Update (C, Data);
      return Finish (C);
   end Hash;
end MC_SHA256;

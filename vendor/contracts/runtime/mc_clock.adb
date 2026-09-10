-- SPDX-License-Identifier: BSD-3-Clause
with MC_Posix; with Interfaces.C; with MC_Kernel_Read; with MC_Hex;
package body MC_Clock with SPARK_Mode => Off is
   use type MC_Types.Byte;
   use Interfaces.C;
   procedure Get (Clock : int; Millis : Boolean; Now : out Counter; Status : out Outcome) is
      T : aliased MC_Posix.Timespec;
   begin
      Now := 0; Status := IO_Error;
      if MC_Posix.Clock_Gettime (Clock, T'Access) /= 0 or else T.Sec < 0
        or else T.Nsec < 0 or else T.Nsec >= 1_000_000_000 then return; end if;
      if Millis then
         if T.Sec > long (Counter'Last / 1000 - 1) then Status := Exhausted; return; end if;
         Now := Counter (T.Sec) * 1000 + Counter (T.Nsec / 1_000_000);
      else Now := Counter (T.Sec); end if;
      Status := OK;
   end Get;
   procedure Boottime_Milliseconds (Now : out Counter; Status : out Outcome) is
   begin Get (7, True, Now, Status); end;
   procedure Realtime_Seconds (Now : out Counter; Status : out Outcome) is
   begin Get (0, False, Now, Status); end;

   procedure Read_Boot_ID (ID : out Identity; Status : out Outcome) is
      B : Bytes (1 .. 37); Used : Natural;
      H : String (1 .. 32); P : Natural := 0;
   begin
      ID := Zero_Identity;
      MC_Kernel_Read.Read (MC_Kernel_Read.Boot_ID,B,Used,Status);
      if Status /= OK then return; end if;
      Status := Invalid_Input;
      if Used /= 37 or else B (37) /= 10 then return; end if;
      for J in 1 .. 36 loop
         if J in 9 | 14 | 19 | 24 then
            if B (J) /= Character'Pos ('-') then return; end if;
         else
            P := P+1; H (P) := Character'Val (B (J));
         end if;
      end loop;
      MC_Hex.Decode (H,ID,Status);
      if Status = OK and then ID = Zero_Identity then Status := Invalid_Input; end if;
   exception when others => ID := Zero_Identity; Status := IO_Error;
   end Read_Boot_ID;
end MC_Clock;

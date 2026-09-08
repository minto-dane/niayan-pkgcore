-- SPDX-License-Identifier: MIT
package body MC_Numbers with SPARK_Mode is
   procedure Parse(S : String; N : out Counter; Status : out Outcome) is
      D : Counter;
   begin
      N:=0; Status:=Invalid_Input; if S'Length=0 or else S'Length>19 then return; end if;
      if S'Length>1 and then S(S'First)='0' then return; end if;
      for C of S loop
         if C not in '0'..'9' then return; end if; D:=Character'Pos(C)-48;
         if N>(Counter'Last-D)/10 then return; end if; N:=N*10+D;
      end loop; Status:=OK;
   end;
   function Image(N : Counter) return String is
      S : String(1..19):=(others=>'0');
      Remaining : Counter:=N;
      First : Positive range 1..19:=1;
   begin
      for I in reverse S'Range loop
         S(I):=Character'Val(48+Remaining mod 10);
         Remaining:=Remaining/10;
         if Remaining=0 then First:=I; exit; end if;
      end loop;
      pragma Assert(Remaining=0);
      declare
         -- Preserve the index origin of the previous trimmed Counter'Image.
         Last : constant Positive:=21-First;
         Result : constant String(2..Last):=S(First..S'Last);
      begin return Result; end;
   end;
end MC_Numbers;

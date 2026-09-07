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
      S : constant String:=Counter'Image(N);
   begin return S(S'First+1..S'Last); end;
end MC_Numbers;

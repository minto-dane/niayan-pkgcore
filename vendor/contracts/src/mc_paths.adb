-- SPDX-License-Identifier: MIT
package body MC_Paths with SPARK_Mode is
   function Safe_Component (Value : String) return Boolean is
   begin
      if Value'Length = 0 or else Value'Length > 255
        or else Value = "." or else Value = ".."
      then
         return False;
      end if;
      for C of Value loop
         if not (C in 'a' .. 'z' or else C in 'A' .. 'Z'
                 or else C in '0' .. '9' or else C = '_' or else C = '-'
                 or else C = '.' or else C = '+' or else C = '@')
         then
            return False;
         end if;
      end loop;
      return True;
   end Safe_Component;
   function Safe_Relative (Value : String) return Boolean is
      Start : Integer := Value'First;
   begin
      if Value'Length = 0 or else Value'Length > 4_096
        or else Value (Value'First) = '/' or else Value (Value'Last) = '/'
        or else Value'Last = Integer'Last
      then
         return False;
      end if;
      for J in Value'Range loop
         pragma Loop_Invariant (Start in Value'First .. J);
         if Value (J) = '/' then
            if J = Start or else not Safe_Component (Value (Start .. J - 1)) then
               return False;
            end if;
            Start := J + 1;
         end if;
      end loop;
      return Safe_Component (Value (Start .. Value'Last));
   end Safe_Relative;
end MC_Paths;

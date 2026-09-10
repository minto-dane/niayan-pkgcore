-- SPDX-License-Identifier: BSD-3-Clause
package body MC_Text with SPARK_Mode is
   function Length (V : Value) return Natural is (V.Used);
   function Image (V : Value) return String is (V.Data (1 .. V.Used));
   procedure Set (V : out Value; S : String; Status : out Outcome) is
   begin
      V := (others => <>); Status := Invalid_Input;
      if S'Length > Max_Length then return; end if;
      for C of S loop
         if Character'Pos (C) < 32 or else Character'Pos (C) > 126 then return; end if;
      end loop;
      V.Used := S'Length; V.Data (1 .. V.Used) := S; Status := OK;
   end Set;
   function Equal (A, B : Value) return Boolean is (Image (A) = Image (B));
   function Identifier (S : String) return Boolean is
   begin
      if S'Length = 0 or else S'Length > 200 then return False; end if;
      if not (S (S'First) in 'a' .. 'z' or else S (S'First) in 'A' .. 'Z'
              or else S (S'First) in '0' .. '9') then return False; end if;
      for C of S loop
         if not (C in 'a' .. 'z' or else C in 'A' .. 'Z' or else C in '0' .. '9'
                 or else C = '_' or else C = '-' or else C = '.' or else C = '@')
         then return False; end if;
      end loop;
      return True;
   end Identifier;
   function HTTPS_URL (S : String) return Boolean is
      Slash : Natural := 0;
      Host_Has_Letter : Boolean := False;
   begin
      if S'Length < 10 or else S'Length > Max_Length or else
        S (S'First .. S'First + 7) /= "https://" then return False; end if;
      for J in S'First + 8 .. S'Last loop
         if S (J) = '/' then Slash := J; exit; end if;
         if S (J) in 'a' .. 'z' or else S (J) in 'A' .. 'Z' then
            Host_Has_Letter := True;
         end if;
         if not (S (J) in 'a' .. 'z' or else S (J) in 'A' .. 'Z'
            or else S (J) in '0' .. '9' or else S (J) = '-' or else S (J) = '.')
         then return False; end if;
      end loop;
      -- Explicit policy profile: DNS names, HTTPS/443, no userinfo, query,
      -- fragment, IP literal, custom port or escaped path. No redirects.
      if Slash = 0 or else Slash = S'First + 8 or else not Host_Has_Letter
      then return False; end if;
      for J in Slash .. S'Last loop
         if not (S (J) in 'a' .. 'z' or else S (J) in 'A' .. 'Z'
            or else S (J) in '0' .. '9' or else S (J) in '/' | '-' | '_' | '.' | '+')
         then return False; end if;
      end loop;
      return True;
   end HTTPS_URL;
end MC_Text;

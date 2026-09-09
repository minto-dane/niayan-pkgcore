-- SPDX-License-Identifier: MIT
with MC_SHA256; with Pkg_Deb_Versions;
package body Pkg_Deb_Relations with SPARK_Mode => Off is
   use Pkg_Deb_Semantics;
   function Field_Name (Kind : Field_Kind) return String is
   begin
      case Kind is
         when Depends => return "depends";
         when Pre_Depends => return "pre-depends";
         when Recommends => return "recommends";
         when Suggests => return "suggests";
         when Enhances => return "enhances";
         when Breaks => return "breaks";
         when Conflicts => return "conflicts";
         when Replaces => return "replaces";
         when Provides => return "provides";
         when Built_Using => return "built-using";
         when Static_Built_Using => return "static-built-using";
      end case;
   end Field_Name;
   function Count (Value : Expression) return Natural is (Value.Atom_Count);
   function Groups (Value : Expression) return Natural is (Value.Group_Count);
   function Kind_Of (Value : Expression) return Field_Kind is (Value.Kind);
   function Control_Hash (Value : Expression) return Digest is (Value.Hash);
   function White (C : Character) return Boolean is (C in ' ' | ASCII.HT);
   function Alnum (C : Character) return Boolean is (C in 'a' .. 'z' | '0' .. '9');
   function Name_Char (C : Character) return Boolean is (Alnum (C) or else C in '+' | '-' | '.');
   procedure Parse (Value : String; Kind : Field_Kind;
                    Result : out Expression; Status : out Outcome) is
      Candidate : Expression;
      P : Positive := 1; Start : Positive; Current : Atom_Position;
      function At_End return Boolean is (P > Candidate.Used);
      function Ch return Character is (if At_End then ASCII.NUL else Candidate.Text (P));
      procedure Skip is
      begin while not At_End and then White (Ch) loop P := P + 1; end loop; end Skip;
      function Part (S : Span) return String is (Candidate.Text (S.First .. S.Last));
   begin
      Result := (others => <>); Status := Invalid_Input;
      if Value'Length > Max_Value then Status := Exhausted; return; end if;
      if Value'Length = 0 then return; end if;
      Candidate.Text (1 .. Value'Length) := Value; Candidate.Used := Value'Length; Candidate.Kind := Kind;
      -- A binary relationship is simple ASCII; source templates, profiles,
      -- architecture restrictions and substituted variables are not binary input.
      for C of Value loop
         if C not in ' ' .. '~' and then C /= ASCII.HT then return; end if;
      end loop;
      Skip; if At_End then return; end if;
      Candidate.Group_Count := 1;
      loop
         if Candidate.Atom_Count = Max_Atoms then Status := Exhausted; return; end if;
         Current := (others => <>); Current.Group_Number := Candidate.Group_Count;
         Start := P; if not Alnum (Ch) then return; end if;
         while not At_End and then Name_Char (Ch) loop P := P + 1; end loop;
         if P - Start < 2 then return; end if;
         if P - Start > MC_Text.Max_Length then Status := Exhausted; return; end if;
         Current.Name := (Start, P - 1);
         if Ch = ':' then
            P := P + 1; Start := P;
            if not Alnum (Ch) then return; end if;
            while not At_End and then (Alnum (Ch) or else Ch = '-') loop P := P + 1; end loop;
            if P - Start > MC_Text.Max_Length then Status := Exhausted; return; end if;
            Current.Architecture := (Start, P - 1);
            if Kind in Built_Using | Static_Built_Using then return; end if;
         end if;
         Skip;
         if Ch = '(' then
            P := P + 1; Skip;
            case Ch is
               when '=' => Current.Operator := Exactly; P := P + 1;
               when '<' =>
                  P := P + 1;
                  if Ch = '<' then Current.Operator := Less_Than;
                  elsif Ch = '=' then Current.Operator := At_Most;
                  else return; end if;
                  P := P + 1;
               when '>' =>
                  P := P + 1;
                  if Ch = '>' then Current.Operator := Greater_Than;
                  elsif Ch = '=' then Current.Operator := At_Least;
                  else return; end if;
                  P := P + 1;
               when others => return;
            end case;
            Skip; Start := P;
            while not At_End and then not White (Ch) and then Ch /= ')' loop P := P + 1; end loop;
            if Start = P then return; end if;
            Current.Version := (Start, P - 1);
            if not Pkg_Deb_Versions.Valid (Part (Current.Version)) then return; end if;
            Skip; if Ch /= ')' then return; end if; P := P + 1; Skip;
         end if;
         if Kind = Provides and then Current.Operator not in Any_Version | Exactly then return; end if;
         if Kind in Built_Using | Static_Built_Using and then Current.Operator /= Exactly then return; end if;
         Candidate.Atom_Count := Candidate.Atom_Count + 1;
         Candidate.Atoms (Candidate.Atom_Count) := Current;
         exit when At_End;
         if Ch = '|' then
            if Kind not in Depends | Pre_Depends | Recommends | Suggests then return; end if;
         elsif Ch = ',' then
            if Candidate.Group_Count = Max_Atoms then Status := Exhausted; return; end if;
            Candidate.Group_Count := Candidate.Group_Count + 1;
         else return; end if;
         P := P + 1; Skip; if At_End then return; end if;
      end loop;
      Result := Candidate; Status := OK;
   exception
      when Storage_Error => Result := (others => <>); Status := Exhausted;
      when others => Result := (others => <>); Status := Invalid_Input;
   end Parse;
   procedure Read_Field (Raw : Bytes; Fields : Pkg_Deb_Fields.Document;
                         Kind : Field_Kind; Result : out Expression; Status : out Outcome) is
      Buffer : Bytes (1 .. Max_Value); Used : Natural;
   begin
      Result := (others => <>); Status := Invalid_Input;
      if Raw'Length > Pkg_Deb_Fields.Max_Control then Status := Exhausted; return; end if;
      -- Even absent fields must not be asserted from an unrelated document.
      if Pkg_Deb_Fields.Content_Hash (Fields) = Zero_Digest
        or else MC_SHA256.Hash (Raw) /= Pkg_Deb_Fields.Content_Hash (Fields) then return; end if;
      if not Pkg_Deb_Fields.Has_Field (Fields, Field_Name (Kind)) then
         Result.Kind := Kind; Result.Hash := Pkg_Deb_Fields.Content_Hash (Fields); Status := OK; return;
      end if;
      Pkg_Deb_Fields.Read_Value (Raw, Fields, Field_Name (Kind), Pkg_Deb_Fields.Simple, Buffer, Used, Status);
      if Status /= OK then return; end if;
      declare
         Text : String (1 .. Used);
      begin
         for I in Text'Range loop Text (I) := Character'Val (Buffer (I)); end loop;
         Parse (Text, Kind, Result, Status);
      end;
      if Status = OK then Result.Hash := Pkg_Deb_Fields.Content_Hash (Fields); end if;
   exception
      when Storage_Error => Result := (others => <>); Status := Exhausted;
      when others => Result := (others => <>); Status := Invalid_Input;
   end Read_Field;
   procedure Validate_All (Raw : Bytes; Fields : Pkg_Deb_Fields.Document; Status : out Outcome) is
      Value : Expression;
   begin
      for Kind in Field_Kind loop
         Read_Field (Raw, Fields, Kind, Value, Status); if Status /= OK then return; end if;
      end loop;
   end Validate_All;
   procedure Read_Atom (Value : Expression; Index : Positive; Result : out Atom; Status : out Outcome) is
      procedure Get (S : Span; Text : out MC_Text.Value) is
      begin
         Text := MC_Text.Empty;
         if S.First /= 0 then MC_Text.Set (Text, Value.Text (S.First .. S.Last), Status); end if;
      end Get;
      Candidate : Atom;
   begin
      Result := (others => <>); Status := Invalid_Input;
      if Index > Value.Atom_Count then return; end if;
      Status := OK;
      Get (Value.Atoms (Index).Name, Candidate.Name); if Status /= OK then return; end if;
      Get (Value.Atoms (Index).Architecture, Candidate.Architecture); if Status /= OK then return; end if;
      Get (Value.Atoms (Index).Version, Candidate.Version); if Status /= OK then return; end if;
      Candidate.Operator := Value.Atoms (Index).Operator;
      Candidate.Group_Number := Value.Atoms (Index).Group_Number;
      Result := Candidate;
   end Read_Atom;
end Pkg_Deb_Relations;

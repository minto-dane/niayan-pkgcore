-- SPDX-License-Identifier: MIT
with Pkg_Deb_Versions;
package body Pkg_Deb_Semantics with SPARK_Mode is
   procedure Matches (Need : Requirement; Fact : Capability;
      Satisfied : out Boolean; Status : out Outcome) is
      use Pkg_Deb_Versions;
      Order : Ordering;
      subtype Version_Relation is Relation range Less_Than .. Greater_Than;
   begin
      Satisfied := False; Status := Invalid_Input;
      if MC_Text.Length (Need.Name) = 0 or else MC_Text.Length (Fact.Name) = 0 then return; end if;
      if Fact.Arch = Unsupported_Architecture then Status := Unsupported; return; end if;
      if Fact.Arch = Independent_All and then Fact.Multi = Same then return; end if;
      if Need.Operator /= Any_Version and then not Valid (MC_Text.Image (Need.Version)) then return; end if;
      if Fact.Versioned and then not Valid (MC_Text.Image (Fact.Version)) then return; end if;
      if (not Fact.Versioned and then MC_Text.Length (Fact.Version) /= 0)
        or else (Need.Operator = Any_Version and then MC_Text.Length (Need.Version) /= 0) then return; end if;
      Status := OK;
      if not MC_Text.Equal (Need.Name, Fact.Name) then return; end if;
      if Need.Arch = Any_Architecture and then Fact.Multi /= Allowed then return; end if;
      if Need.Operator = Any_Version then Satisfied := True; return; end if;
      if not Fact.Versioned then return; end if;
      Order := Compare (MC_Text.Image (Fact.Version), MC_Text.Image (Need.Version));
      case Version_Relation(Need.Operator) is
         when Less_Than => Satisfied := Order = Older;
         when At_Most => Satisfied := Order /= Newer;
         when Exactly => Satisfied := Order = Equal;
         when At_Least => Satisfied := Order /= Older;
         when Greater_Than => Satisfied := Order = Newer;
      end case;
   end Matches;
   function Requires_Check (Kind : Relation_Kind; At_Point : Boundary) return Boolean is
   begin
      case Kind is
         when Depends => return At_Point in Before_Configure | Ready_Endpoint;
         when Pre_Depends => return At_Point in Before_Unpack | Before_Configure | Ready_Endpoint;
         when Conflicts => return At_Point in Before_Unpack | Ready_Endpoint;
         when Breaks => return At_Point in Before_Configure | Ready_Endpoint;
         when Replaces => return At_Point = Before_Unpack;
         when Built_Using | Static_Built_Using => return At_Point = Source_Retention;
         when Recommends | Suggests | Enhances => return False; -- Explicit product policy handles weak desires.
      end case;
   end Requires_Check;
end Pkg_Deb_Semantics;

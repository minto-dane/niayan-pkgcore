-- SPDX-License-Identifier: BSD-3-Clause
with Pkg_EVR; with Pkg_Versions;
package body Pkg_Dependency with SPARK_Mode is
   procedure Parse(Text : String; E : out Expression; Status : out Outcome) is
      P : Positive;
      Failed : Boolean:=False; Parsed_Root : Node_ID;
      function Cursor_Valid return Boolean is
        (Text'Length in 1..4_096 and then Text'Last<Integer'Last
         and then P in Text'First..Text'Last+1);
      procedure Read_Word(Word : out MC_Text.Value) with
        Pre => Cursor_Valid, Post => Cursor_Valid and then P>=P'Old
          and then (if not Failed then MC_Text.Length(Word)=P-P'Old)
          and then (if Failed'Old then Failed)
      is
         First : constant Natural:=P; Depth : Natural:=0; Local_Status : Outcome;
      begin
         while P<=Text'Last loop
            pragma Loop_Invariant(Cursor_Valid and then P>=First and then Depth<=P-First);
            pragma Loop_Variant(Increases=>P);
            if Text(P)=' ' then exit;
            elsif Text(P)='(' then Depth:=Depth+1;
            elsif Text(P)=')' then if Depth=0 then exit; else Depth:=Depth-1; end if;
            end if;
            P:=P+1;
         end loop;
         if Depth/=0 then Failed:=True; end if;
         MC_Text.Set(Word,Text(First..P-1),Local_Status);
         if Local_Status/=OK then Failed:=True; end if;
      end Read_Word;
      procedure Spaces with Pre => Cursor_Valid,
        Post => Cursor_Valid and then P>=P'Old
      is
      begin
         while P<=Text'Last and then Text(P)=' ' loop
            pragma Loop_Invariant(Cursor_Valid and then P>=P'Loop_Entry);
            pragma Loop_Variant(Increases=>P);
            P:=P+1;
         end loop;
      end;
      procedure Add(N : Node; Result : out Node_ID) with
        Post => E.Count>=E.Count'Old and then (if Failed'Old then Failed)
      is
      begin
         Result:=0;
         if E.Count=Max_Nodes then Failed:=True; return; end if;
         E.Count:=E.Count+1; E.Nodes(E.Count):=N; Result:=E.Count;
      end;
      procedure Operand(Depth : Natural; Result : out Node_ID) with
        Pre => Cursor_Valid,
        Post => Cursor_Valid and then P>=P'Old and then (if not Failed then P>P'Old)
          and then (if Failed'Old then Failed),
        Subprogram_Variant => (Increases=>Depth);
      procedure Operand(Depth : Natural; Result : out Node_ID) is
         Entry_Pos : constant Positive:=P;
         L,R,A : Node_ID; Word : MC_Text.Value; N : Node; Op : Operator; S : Outcome; First_Op : Operator:=Capability;
      begin
         Result:=0;
         if Depth>32 then Failed:=True; return; end if;
         Spaces; if P>Text'Last then Failed:=True; return; end if;
         if Text(P)='(' then
            P:=P+1; Operand(Depth+1,L); if Failed then return; end if;
            loop
               pragma Loop_Invariant(Cursor_Valid and then P>=P'Loop_Entry and then P>Entry_Pos);
               pragma Loop_Variant(Increases=>P);
               Spaces; if P>Text'Last then Failed:=True; return; end if;
               if Text(P)=')' then
                  if First_Op=Capability then Failed:=True; return; end if;
                  P:=P+1; Result:=L; return;
               end if;
               Read_Word(Word);
               declare W : constant String:=MC_Text.Image(Word); begin
                  if W="and" then Op:=And_Op; elsif W="or" then Op:=Or_Op;
                  elsif W="with" then Op:=With_Op; elsif W="without" then Op:=Without_Op;
                  elsif W="if" then Op:=If_Op; elsif W="unless" then Op:=Unless_Op;
                  else Failed:=True; return; end if;
               end;
               if First_Op/=Capability and then Op/=First_Op then Failed:=True; return; end if;
               First_Op:=Op; Operand(Depth+1,R); if Failed then return; end if;
               A:=0; Spaces;
               if Op in If_Op | Unless_Op then
                  if P<=Text'Last and then Text(P)/=')' then
                     Read_Word(Word);
               declare W : constant String:=MC_Text.Image(Word); begin
                        if W/="else" then Failed:=True; return; end if;
                     end;
                     Operand(Depth+1,A); Spaces;
                  end if;
                  if P>Text'Last or else Text(P)/=')' then Failed:=True; return; end if;
               end if;
               N:=(Op=>Op,Left=>L,Right=>R,Alternative=>A,others=><>); Add(N,L);
               if Op in If_Op | Unless_Op then P:=P+1; Result:=L; return; end if;
            end loop;
         else
            N.Op:=Capability;
            Read_Word(Word);
               declare W : constant String:=MC_Text.Image(Word); begin
               if W'Length=0 then Failed:=True; return; end if;
               MC_Text.Set(N.Name,W,S); if S/=OK then Failed:=True; return; end if;
            end;
            Spaces;
            if P<=Text'Last and then Text(P) in '<' | '>' | '=' then
               Read_Word(Word);
               declare W : constant String:=MC_Text.Image(Word); begin
                  if W="<" then N.Comparison:=LT; elsif W="<=" then N.Comparison:=LE;
                  elsif W="=" then N.Comparison:=EQ; elsif W=">=" then N.Comparison:=GE;
                  elsif W=">" then N.Comparison:=GT; else Failed:=True; return; end if;
               end;
               Spaces;
               Read_Word(Word);
               declare W : constant String:=MC_Text.Image(Word); V : Pkg_EVR.EVR; begin
                  MC_Text.Set(N.Version,W,S); if S=OK then Pkg_EVR.Parse(W,V,S); end if;
                  if S/=OK then Failed:=True; return; end if;
                  if MC_Text.Length(V.Version)=0 then Failed:=True; return; end if;
               end;
            end if;
            pragma Assert(if not Failed then P>Entry_Pos);
            Add(N,Result); return;
         end if;
      end Operand;
   begin
      E:=(others=><>); Status:=Invalid_Input;
      if Text'Length=0 or else Text'Length>4096 or else Text'Last=Integer'Last then return; end if;
      P:=Text'First;
      for C of Text loop if Character'Pos(C)<32 or else Character'Pos(C)>126 then return; end if; end loop;
      Operand(0,Parsed_Root); E.Root:=Parsed_Root; Spaces;
      if not Failed and then P=Text'Last+1 and then Well_Formed(E) then Status:=OK; end if;
   end Parse;
   procedure Evaluate(E : Expression; Providers : Provider_Array; Count : Natural;
      Selected : Selection; Satisfied : out Boolean; Status : out Outcome) is
      use type Pkg_Versions.Ordering;
      type Values is array(Positive range 1..Max_Nodes) of Boolean;
      type Per_Package is array(Positive range 1..Max_Packages) of Values;
      -- The single-package evaluation is needed by with/without; existential
      -- package witnesses must not be replaced by unrelated global booleans.
      Single : Per_Package:=(others=>(others=>False)); Global : Values:=(others=>False);
      A,B : Pkg_EVR.EVR; O : Pkg_Versions.Ordering; Matched : Boolean;
      subtype Version_Relation is Relation range LT..GT;
      function Boolean_Value(N : Node; V : Values) return Boolean with
        Pre => (if N.Op/=Capability then N.Left in V'Range and then N.Right in V'Range)
      is
      begin
         case N.Op is
            when And_Op | With_Op => return V(N.Left) and V(N.Right);
            when Or_Op => return V(N.Left) or V(N.Right);
            when Without_Op => return V(N.Left) and not V(N.Right);
            when If_Op => return (if V(N.Right) then V(N.Left) elsif N.Alternative=0 then True else V(N.Alternative));
            when Unless_Op => return (if not V(N.Right) then V(N.Left) elsif N.Alternative=0 then True else V(N.Alternative));
            when Capability => return False;
         end case;
      end;
   begin
      Satisfied:=False; Status:=Invalid_Input; if not Well_Formed(E) then return; end if;
      for I in 1..E.Count loop
         declare N : Node renames E.Nodes(I); begin
            if N.Op=Capability then
               if N.Comparison/=Any_Version then Pkg_EVR.Parse(MC_Text.Image(N.Version),B,Status); if Status/=OK then return; end if; end if;
               for J in 1..Count loop
                  if Providers(J).Package_Index=0 then Status:=Invalid_Input; return; end if;
                  if Selected(Providers(J).Package_Index) and then MC_Text.Equal(N.Name,Providers(J).Name) then
                     Matched:=N.Comparison=Any_Version;
                     if N.Comparison/=Any_Version and then Providers(J).Versioned then
                        Pkg_EVR.Parse(MC_Text.Image(Providers(J).Version),A,Status); if Status/=OK then return; end if;
                        O:=Pkg_EVR.Compare(A,B,Dependency_Match=>True);
                        case Version_Relation(N.Comparison) is
                           when LT => Matched:=O=Pkg_Versions.Older;
                           when LE => Matched:=O/=Pkg_Versions.Newer;
                           when EQ => Matched:=O=Pkg_Versions.Equal;
                           when GE => Matched:=O/=Pkg_Versions.Older;
                           when GT => Matched:=O=Pkg_Versions.Newer;
                        end case;
                     end if;
                     if Matched then Global(I):=True; Single(Providers(J).Package_Index)(I):=True; end if;
                  end if;
               end loop;
            else
               for J in 1..Max_Packages loop
                  if Selected(J) then Single(J)(I):=Boolean_Value(N,Single(J)); end if;
               end loop;
               if N.Op in With_Op | Without_Op then
                  for J in 1..Max_Packages loop Global(I):=Global(I) or Single(J)(I); end loop;
               else Global(I):=Boolean_Value(N,Global); end if;
            end if;
         end;
      end loop;
      Satisfied:=Global(E.Root); Status:=OK;
   end Evaluate;
end Pkg_Dependency;

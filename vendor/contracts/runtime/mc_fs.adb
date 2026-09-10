-- SPDX-License-Identifier: BSD-3-Clause
with Interfaces.C; with System; with MC_Posix; with MC_Paths;
with MC_SHA256; with MC_Codec;
package body MC_FS with SPARK_Mode => Off is
   use Interfaces.C; use MC_Posix;
   use type Byte; use type Word; use type Wide; use type System.Bit_Order;
   type Stat_Buffer is array (Natural range 0 .. 255) of Byte;
   for Stat_Buffer'Alignment use 8;
   function LE32 (B : Stat_Buffer; P : Natural) return Word is
     (Word (B(P)) + Word (B(P+1))*256 + Word(B(P+2))*65_536 + Word(B(P+3))*16_777_216);
   function LE64 (B : Stat_Buffer; P : Natural) return Wide is
     (Wide(LE32(B,P)) + Wide(LE32(B,P+4))*2**32);
   function Errno return int is (Errno_Location.all);
   procedure Drop (D : in out int) is
      Result : int;
      pragma Unreferenced (Result);
   begin
      if D >= 0 then Result := MC_Posix.Close (D); end if;
      D := -1;
   end Drop;
   procedure Stat_FD (D : int; V : out Entry_Info; Status : out Outcome) is
      B : aliased Stat_Buffer := (others => 0);
      Empty : aliased char_array := To_C ("");
      Raw_Mode : Word;
      Required : constant Word := 16#13DF#;
   begin
      V := (others => <>); Status := Unsupported;
      if long'Size /= 64 or else size_t'Size /= 64 or else System.Word_Size /= 64
        or else System.Default_Bit_Order /= System.Low_Order_First then return; end if;
      Status := IO_Error;
      if MC_Posix.Statx (D, Empty'Address, AT_EMPTY_PATH, unsigned(Required), B'Address) /= 0
        then return; end if;
      if (LE32(B,0) and Required) /= Required then Status := Unsupported; return; end if;
      Raw_Mode := Word(B(28)) + Word(B(29))*256;
      case Raw_Mode and 8#170000# is
         when 8#100000# => V.Kind := Regular;
         when 8#040000# => V.Kind := Directory;
         when 8#120000# => V.Kind := Symbolic_Link;
         when others => V.Kind := Other;
      end case;
      V.Mode := Raw_Mode and 8#7777#;
      V.UID := LE32(B,20); V.GID := LE32(B,24); V.Links := LE32(B,16);
      V.Inode := LE64(B,32); V.Mount_ID := LE64(B,144);
      V.Device_Major := LE32(B,136); V.Device_Minor := LE32(B,140);
      if LE64(B,40) > Wide(Counter'Last) or else LE64(B,112) > Wide(Counter'Last)
        or else LE64(B,96) > Wide(Counter'Last)
        or else LE32(B,104) >= 1_000_000_000
        or else LE32(B,120) >= 1_000_000_000 then Status := Unsupported; return; end if;
      V.Size := Counter(LE64(B,40)); V.Mtime_Sec := Counter(LE64(B,112));
      V.Mtime_Nsec := Natural(LE32(B,120));
      V.Ctime_Sec := Counter(LE64(B,96)); V.Ctime_Nsec := Natural(LE32(B,104));
      Status := OK;
   end Stat_FD;
   function Open_Beneath (D : int; Name : String; Flags : int;
                          Mode : unsigned := 0; Cross_Mounts : Boolean := False) return int is
      C_Name : aliased char_array := To_C (Name);
      How : aliased Open_How :=
        (Flags => unsigned_long(Flags), Mode => unsigned_long(Mode),
         Resolve => (if Cross_Mounts then 14 else 15));
      Result : long;
   begin
      Result := Openat2_Call (437, D, C_Name'Address, How'Address, Open_How'Size/8);
      if Result < 0 or else Result > long(int'Last) then return -1; end if;
      return int(Result);
   end Open_Beneath;
   procedure Open_Root (Path : String; R : in out Root; Status : out Outcome;
                        Private_Only : Boolean := False) is
      Top : aliased char_array := To_C ("/"); D, N : int := -1;
      V : Entry_Info;
   begin
      Status := Invalid_Input;
      if R.Handle /= -1 then Status := Conflict; return; end if;
      if Path'Length < 1 or else Path'Length > 4096 or else Path(Path'First) /= '/'
        or else (Path /= "/" and then not MC_Paths.Safe_Relative(Path(Path'First+1 .. Path'Last)))
      then return; end if;
      D := MC_Posix.Open (Top'Address, O_RDONLY+O_DIRECTORY+O_NOFOLLOW+O_CLOEXEC, 0);
      if D < 0 then Status := IO_Error; return; end if;
      if Path = "/" then N := D; D := -1;
      else N := Open_Beneath(D,Path(Path'First+1 .. Path'Last),O_RDONLY+O_DIRECTORY+O_CLOEXEC,
                            Cross_Mounts => True); end if;
      Drop(D);
      if N < 0 then Status := IO_Error; return; end if;
      Stat_FD(N,V,Status);
      if Status = OK and then
        (V.Kind /= Directory or else (V.Mode and 8#022#) /= 0
         or else (V.UID /= Word(Euid) and then V.UID /= 0)
         or else (Private_Only and then (V.UID /= Word(Euid) or else V.Mode /= 8#700#)))
      then Status := Denied; end if;
      if Status /= OK then Drop(N); return; end if;
      R.Handle := Integer(N); R.Identity := V;
   end Open_Root;
   procedure Root_Info (R : Root; Info : out Entry_Info; Status : out Outcome) is
   begin
      Info := (others => <>); Status := Invalid_Input;
      if R.Handle >= 0 then Stat_FD(int(R.Handle),Info,Status); end if;
   end Root_Info;
   procedure Parent (R : Root; Path : String; D : out int;
                     Name : out MC_Text.Value; Status : out Outcome) is
      Start : Positive := Path'First;
      Next_D : int := -1; V : Entry_Info;
   begin
      D := -1; Name := MC_Text.Empty; Status := Invalid_Input;
      if R.Handle < 0 or else not MC_Paths.Safe_Relative(Path) then return; end if;
      D := MC_Posix.Dup(int(R.Handle),1030,3); -- F_DUPFD_CLOEXEC
      if D < 0 then Status := IO_Error; return; end if;
      for J in Path'Range loop
         if Path(J) = '/' then
            Next_D := Open_Beneath(D,Path(Start .. J-1),O_RDONLY+O_DIRECTORY+O_CLOEXEC);
            Drop(D); D := Next_D;
            if D < 0 then Status := (if Errno = ENOENT then Stale else IO_Error); return; end if;
            Stat_FD(D,V,Status);
            if Status /= OK then Drop(D); return; end if;
            if V.Kind /= Directory or else (V.Mode and 8#022#) /= 0 or else
               (V.UID /= 0 and then V.UID /= Word(Euid)) or else
               V.Mount_ID /= R.Identity.Mount_ID then
               Drop(D); Status := Denied; return;
            end if;
            Start := J+1;
         end if;
      end loop;
      MC_Text.Set(Name,Path(Start .. Path'Last),Status);
      if Status /= OK then Drop(D); end if;
   end Parent;
   procedure Stat (R : Root; Path : String; Info : out Entry_Info; Status : out Outcome) is
      D : int := -1;
   begin
      Info := (others => <>); Status := Invalid_Input;
      if R.Handle < 0 or else not MC_Paths.Safe_Relative(Path) then return; end if;
      -- O_PATH|O_NOFOLLOW with RESOLVE_NO_SYMLINKS permits the final symlink
      -- itself to be inspected, never followed. Intermediate symlinks are refused.
      D := Open_Beneath(int(R.Handle),Path,O_PATH+O_NOFOLLOW+O_CLOEXEC);
      if D < 0 then
         if Errno = ENOENT then Status := OK; else Status := IO_Error; end if;
         return;
      end if;
      Stat_FD(D,Info,Status); Drop(D);
   end Stat;
   procedure Open_Read (R : Root; Path : String; F : in out File; Status : out Outcome) is
      D : int := -1; V : Entry_Info;
   begin
      Status := Invalid_Input;
      if F.Handle >= 0 then Status := Conflict; return; end if;
      if R.Handle < 0 or else not MC_Paths.Safe_Relative(Path) then return; end if;
      D := Open_Beneath(int(R.Handle),Path,O_RDONLY+O_NOFOLLOW+O_NONBLOCK+O_CLOEXEC);
      if D < 0 then Status := IO_Error; return; end if;
      Stat_FD(D,V,Status);
      if Status = OK and then (V.Kind not in Regular | Directory or else
        (V.Kind = Regular and then V.Links /= 1)) then Status := Unsupported; end if;
      if Status /= OK then Drop(D); return; end if;
      F.Handle := Integer(D); F.Writable := False; F.Poisoned := False;
   end Open_Read;
   procedure Open_New_Or_Lock (R : Root; Path : String; Lock_Mode : Boolean;
                              F : in out File; Status : out Outcome;
                              Create_If_Missing : Boolean := True) is
      D, N : int := -1; Name : MC_Text.Value; V : Entry_Info;
   begin
      Status := Invalid_Input;
      if F.Handle >= 0 then Status := Conflict; return; end if;
      if Lock_Mode then
         -- Avoid opening an already visible device/FIFO/socket for read/write.
         -- Private parent ownership is still required; the post-open fstat below
         -- is authoritative. This precheck is not a substitute for that boundary.
         Stat (R,Path,V,Status); if Status /= OK then return; end if;
         if V.Kind /= Absent and then V.Kind /= Regular then Status := Denied; return; end if;
         if V.Kind = Absent and then not Create_If_Missing then Status := Corrupt; return; end if;
      end if;
      Parent(R,Path,D,Name,Status); if Status /= OK then return; end if;
      N := Open_Beneath(D,MC_Text.Image(Name),O_RDWR+O_CLOEXEC+O_NOFOLLOW+O_NONBLOCK+
                        (if Create_If_Missing then O_CREAT else 0)+
                        (if Lock_Mode then 0 else O_EXCL),
                        (if Create_If_Missing then 8#600# else 0));
      if N < 0 then
         Status := (if Errno = EEXIST then Conflict
                    elsif Errno = ENOENT and then not Create_If_Missing then Corrupt
                    else IO_Error);
         Drop(D); return;
      end if;
      Stat_FD(N,V,Status);
      if Status = OK and then (V.Kind /= Regular or else V.UID /= Word(Euid)
         or else V.Links /= 1 or else V.Mode /= 8#600#) then Status := Denied; end if;
      if Status = OK and then Lock_Mode and then Flock(N,LOCK_EX_NB) /= 0 then Status := Conflict; end if;
      if Status = OK and then Fsync(D) /= 0 then Status := Indeterminate; end if;
      Drop(D);
      if Status /= OK then Drop(N); return; end if;
      F.Handle := Integer(N); F.Writable := True; F.Poisoned := False;
   end Open_New_Or_Lock;
   procedure Create_New (R : Root; Path : String; F : in out File; Status : out Outcome) is
   begin Open_New_Or_Lock(R,Path,False,F,Status); end;
   procedure Open_Locked (R : Root; Path : String; F : in out File; Status : out Outcome;
                          Create_If_Missing : Boolean := True) is
   begin Open_New_Or_Lock(R,Path,True,F,Status,Create_If_Missing); end;
   procedure Info (F : File; Value : out Entry_Info; Status : out Outcome) is
   begin
      Value := (others => <>); Status := Invalid_Input;
      if F.Handle >= 0 and then not F.Poisoned then Stat_FD(int(F.Handle),Value,Status); end if;
   end Info;
   procedure Read_At (F : File; Offset : Counter; Data : out Bytes;
                      Count : out Natural; Status : out Outcome) is
      N : long;
   begin
      Data := (others => 0); Count := 0; Status := Invalid_Input;
      if F.Handle < 0 or else F.Poisoned or else Data'Length > 16_777_216
        or else Offset > Counter'Last-Counter(Data'Length) then return; end if;
      while Count < Data'Length loop
         N := Pread(int(F.Handle),Data(Data'First+Count)'Address,
                    size_t(Data'Length-Count),long(Offset+Counter(Count)));
         if N < 0 and then Errno = EINTR then null;
         elsif N < 0 then Status := IO_Error; return;
         elsif N = 0 then Status := OK; return;
         elsif N > long(Data'Length-Count) then Status := IO_Error; return;
         else Count := Count+Natural(N); end if;
      end loop;
      Status := OK;
   end Read_At;
   procedure Write_All (F : in out File; Data : Bytes; Status : out Outcome) is
      Done : Natural := 0; N : long;
   begin
      Status := Invalid_Input;
      if F.Handle < 0 or else not F.Writable or else F.Poisoned then return; end if;
      while Done < Data'Length loop
         N := MC_Posix.Write(int(F.Handle),Data(Data'First+Done)'Address,size_t(Data'Length-Done));
         if N < 0 and then Errno = EINTR then null;
         elsif N <= 0 or else N > long(Data'Length-Done) then
            F.Poisoned := True; Status := Indeterminate; return;
         else Done := Done+Natural(N); end if;
      end loop;
      Status := OK;
   end Write_All;
   procedure Append_Durable (F : in out File; Expected_Length : Counter;
                              Data : Bytes; Status : out Outcome) is
      Position : long;
   begin
      Status := Invalid_Input;
      if F.Handle < 0 or else not F.Writable or else F.Poisoned
        or else Expected_Length > Counter'Last-Counter(Data'Length) then return; end if;
      Position := Lseek(int(F.Handle),0,2);
      if Position < 0 then Status := IO_Error; return; end if;
      if Counter(Position) /= Expected_Length then Status := Conflict; return; end if;
      Write_All(F,Data,Status);
      if Status = OK then Sync(F,Status); end if;
      if Status /= OK then F.Poisoned := True; Status := Indeterminate; end if;
   end Append_Durable;
   procedure Sync (F : File; Status : out Outcome) is
   begin
      Status := Invalid_Input;
      if F.Handle < 0 or else F.Poisoned then return; end if;
      Status := (if Fsync(int(F.Handle)) = 0 then OK else Indeterminate);
   end Sync;
   procedure Sync_Parent (R : Root; Path : String; Status : out Outcome) is
      D : int := -1; Name : MC_Text.Value;
   begin
      Parent(R,Path,D,Name,Status); if Status /= OK then return; end if;
      Status := (if Fsync(D) = 0 then OK else Indeterminate); Drop(D);
   end Sync_Parent;
   procedure Hash (F : File; Limit : Counter; D : out Digest; Size : out Counter; Status : out Outcome) is
      C : MC_SHA256.Context := MC_SHA256.Initialize;
      B : Bytes(1 .. 65_536); Got : Natural; Offset : Counter := 0;
      Initial, Final : Entry_Info;
   begin
      D := Zero_Digest; Size := 0; Info(F,Initial,Status);
      if Status /= OK then return; end if;
      if Initial.Kind /= Regular or else Initial.Size > Limit then Status := Exhausted; return; end if;
      loop
         Read_At(F,Offset,B,Got,Status); if Status /= OK then return; end if;
         exit when Got = 0;
         if Counter(Got) > Limit-Offset then Status := Exhausted; return; end if;
         MC_SHA256.Update(C,B(1 .. Got)); Offset := Offset+Counter(Got);
      end loop;
      Info(F,Final,Status); if Status /= OK then return; end if;
      if Initial /= Final or else Offset /= Initial.Size then Status := Conflict; return; end if;
      D := MC_SHA256.Finish(C); Size := Offset; Status := OK;
   end Hash;
   procedure Make_Directory (R : Root; Path : String; Status : out Outcome) is
      D : int := -1; Name : MC_Text.Value;
   begin
      Parent(R,Path,D,Name,Status); if Status /= OK then return; end if;
      declare C : aliased char_array := To_C(MC_Text.Image(Name)); begin
         if Mkdirat(D,C'Address,8#700#) /= 0 then
            Status := (if Errno = EEXIST then Conflict else IO_Error); Drop(D); return;
         end if;
      end;
      Status := (if Fsync(D) = 0 then OK else Indeterminate); Drop(D);
   end Make_Directory;
   procedure Read_Link (R : Root; Path : String; Target : out MC_Text.Value; Status : out Outcome) is
      D : int := -1; Name : MC_Text.Value; B : aliased char_array(0 .. 4096); N : long;
   begin
      Target := MC_Text.Empty; Parent(R,Path,D,Name,Status); if Status /= OK then return; end if;
      declare C : aliased char_array := To_C(MC_Text.Image(Name)); begin
         N := Readlinkat(D,C'Address,B'Address,B'Length);
      end;
      Drop(D);
      if N < 1 then Status := IO_Error; return; end if;
      if N > 4096 then Status := Exhausted; return; end if;
      MC_Text.Set(Target,To_Ada(B(0 .. size_t(N)-1),Trim_Nul => False),Status);
   end Read_Link;
   procedure Make_Link (R : Root; Path, Target : String; Status : out Outcome) is
      D : int := -1; Name : MC_Text.Value;
   begin
      Status := Invalid_Input;
      -- Symlink text may contain ../ or be absolute; it is never traversed by this
      -- library. Plan policy must constrain the permitted link targets separately.
      if Target'Length = 0 or else Target'Length > 4096 then return; end if;
      for C of Target loop if Character'Pos(C) < 32 or else Character'Pos(C) > 126 then return; end if; end loop;
      Parent(R,Path,D,Name,Status); if Status /= OK then return; end if;
      declare N : aliased char_array := To_C(MC_Text.Image(Name));
              T : aliased char_array := To_C(Target); begin
         if Symlinkat(T'Address,D,N'Address) /= 0 then
            Status := (if Errno = EEXIST then Conflict else IO_Error); Drop(D); return;
         end if;
      end;
      Status := (if Fsync(D) = 0 then OK else Indeterminate); Drop(D);
   end Make_Link;
   procedure Rename (R : Root; From_Path, To_Path : String;
                      No_Replace : Boolean; Status : out Outcome) is
      D1, D2 : int := -1; N1, N2 : MC_Text.Value;
   begin
      Parent(R,From_Path,D1,N1,Status); if Status /= OK then return; end if;
      Parent(R,To_Path,D2,N2,Status); if Status /= OK then Drop(D1); return; end if;
      declare A : aliased char_array := To_C(MC_Text.Image(N1));
              B : aliased char_array := To_C(MC_Text.Image(N2)); begin
         if Renameat2(D1,A'Address,D2,B'Address,(if No_Replace then 1 else 0)) /= 0 then
            Status := (if Errno = EEXIST then Conflict else IO_Error); Drop(D1); Drop(D2); return;
         end if;
      end;
      Status := OK;
      if Fsync(D1) /= 0 or else Fsync(D2) /= 0 then Status := Indeterminate; end if;
      Drop(D1); Drop(D2);
   end Rename;
   procedure Remove (R : Root; Path : String; Is_Directory : Boolean; Status : out Outcome) is
      D : int := -1; Name : MC_Text.Value;
   begin
      Parent(R,Path,D,Name,Status); if Status /= OK then return; end if;
      declare N : aliased char_array := To_C(MC_Text.Image(Name)); begin
         if Unlinkat(D,N'Address,(if Is_Directory then AT_REMOVEDIR else 0)) /= 0 then
            Status := (if Errno = ENOENT then Stale else IO_Error); Drop(D); return;
         end if;
      end;
      Status := (if Fsync(D) = 0 then OK else Indeterminate); Drop(D);
   end Remove;
   procedure Set_Metadata (F : File; Value : Entry_Info; Status : out Outcome) is
      T : aliased Timespec_Pair :=
        (0 => (Sec => 0,Nsec => 1_073_741_822), -- UTIME_OMIT
         1 => (Sec => long(Value.Mtime_Sec),Nsec => long(Value.Mtime_Nsec)));
   begin
      Status := Denied;
      if F.Handle < 0 or else F.Poisoned or else Value.Kind not in Regular | Directory
         or else (Value.Mode and not 8#777#) /= 0 then return; end if;
      -- Ownership before permissions: chown can clear mode bits.
      if Fchown(int(F.Handle),unsigned(Value.UID),unsigned(Value.GID)) /= 0
         or else Fchmod(int(F.Handle),unsigned(Value.Mode)) /= 0 then Status := IO_Error; return; end if;
      if Value.Kind = Regular and then Futimens(int(F.Handle),T'Address) /= 0 then
         Status := IO_Error; return;
      end if;
      Sync(F,Status);
   end Set_Metadata;
   procedure Set_Link_Owner (R : Root; Path : String; UID, GID : Word; Status : out Outcome) is
      D : int := -1; Name : MC_Text.Value;
   begin
      Parent(R,Path,D,Name,Status); if Status /= OK then return; end if;
      declare N : aliased char_array := To_C(MC_Text.Image(Name)); begin
         if Fchownat(D,N'Address,unsigned(UID),unsigned(GID),AT_SYMLINK_NOFOLLOW) /= 0 then
            Status := IO_Error; Drop(D); return;
         end if;
      end;
      Status := (if Fsync(D) = 0 then OK else Indeterminate); Drop(D);
   end Set_Link_Owner;
   function Llistxattr(P, B : System.Address; N : size_t) return long
     with Import,Convention=>C,External_Name=>"llistxattr";
   function Lgetxattr(P, Name, B : System.Address; N : size_t) return long
     with Import,Convention=>C,External_Name=>"lgetxattr";
   function Lsetxattr(P, Name, B : System.Address; N : size_t; Flags : int) return int
     with Import,Convention=>C,External_Name=>"lsetxattr";
   function Lremovexattr(P, Name : System.Address) return int
     with Import,Convention=>C,External_Name=>"lremovexattr";
   function X_List(D : int; Link : String; B : System.Address; N : size_t) return long is
      C : aliased char_array:=To_C(Link);
   begin
      if Link="" then return Flistxattr(D,B,N); else return Llistxattr(C'Address,B,N); end if;
   end;
   function X_Get(D : int; Link : String; Name,B : System.Address; N : size_t) return long is
      C : aliased char_array:=To_C(Link);
   begin
      if Link="" then return Fgetxattr(D,Name,B,N); else return Lgetxattr(C'Address,Name,B,N); end if;
   end;
   function X_Set(D : int; Link : String; Name,B : System.Address; N : size_t) return int is
      C : aliased char_array:=To_C(Link);
   begin
      if Link="" then return Fsetxattr(D,Name,B,N,0); else return Lsetxattr(C'Address,Name,B,N,0); end if;
   end;
   function X_Remove(D : int; Link : String; Name : System.Address) return int is
      C : aliased char_array:=To_C(Link);
   begin
      if Link="" then return Fremovexattr(D,Name); else return Lremovexattr(C'Address,Name); end if;
   end;
   procedure Get_Attributes (Descriptor : int; Link : String; Data : out Bytes;
                             Used : out Natural; Status : out Outcome) is
      Names : aliased char_array(0 .. 8191); N, L : long;
      type Name_Array is array(1 .. 64) of MC_Text.Value;
      List : Name_Array; Count : Natural := 0; Start : size_t := 0;
      Temp : MC_Text.Value; P : Natural := 2;
   begin
      Data := (others => 0); Used := 0; Status := Invalid_Input;
      if Descriptor < 0 or else Data'Length < 2 or else Data'First /= 1 then return; end if;
      N := X_List(Descriptor,Link,Names'Address,Names'Length);
      if N < 0 then Status := IO_Error; return; end if;
      if N>0 then
      for J in 0 .. size_t(N) - 1 loop
         if Names(J) = nul then
            if J = Start or else Count = List'Length then Status := Exhausted; return; end if;
            Count := Count+1;
            MC_Text.Set(List(Count),To_Ada(Names(Start .. J-1),Trim_Nul => False),Status);
            if Status /= OK then return; end if; Start := J+1;
         end if;
      end loop;
      end if;
      if Start /= size_t(N) then Status := Corrupt; return; end if;
      -- Canonical bytewise ASCII order, independent of kernel list order.
      for I in 1 .. Count loop
         for J in I+1 .. Count loop
            if MC_Text.Image(List(J)) < MC_Text.Image(List(I)) then Temp:=List(I); List(I):=List(J); List(J):=Temp; end if;
         end loop;
      end loop;
      MC_Codec.Put16(Data,1,Count);
      for I in 1 .. Count loop
         declare Name : constant String := MC_Text.Image(List(I));
                 C : aliased char_array := To_C(Name); begin
            L := X_Get(Descriptor,Link,C'Address,System.Null_Address,0);
            if L < 0 or else L > 65_536 then Status := Exhausted; return; end if;
            if P+6+Name'Length+Natural(L) > Data'Length then Status := Exhausted; return; end if;
            MC_Codec.Put16(Data,P+1,Name'Length); MC_Codec.Put32(Data,P+3,Word(L)); P:=P+6;
            for Ch of Name loop P:=P+1; Data(P):=Byte(Character'Pos(Ch)); end loop;
            if L > 0 then
               if X_Get(Descriptor,Link,C'Address,Data(P+1)'Address,size_t(L)) /= L then Status:=Conflict; return; end if;
            end if;
            P:=P+Natural(L);
         end;
      end loop;
      Used:=P; Status:=OK;
   end Get_Attributes;
   procedure Set_Attributes (Descriptor : int; Link : String; Data : Bytes; Status : out Outcome) is
      type Attr is record Name : MC_Text.Value; Offset, Length : Natural := 0; end record;
      type Attr_Array is array(1 .. 64) of Attr;
      Desired : Attr_Array; Count, P, NL, VL : Natural;
      Existing : Bytes(1 .. Max_Xattr_Bytes); E_Used, E_Count, EP : Natural;
      Found : Boolean;
   begin
      Status := Invalid_Input;
      if Descriptor < 0 or else Data'First /= 1 or else Data'Length < 2 then return; end if;
      Count := MC_Codec.U16(Data,1); P:=2;
      if Count > Desired'Length then return; end if;
      for I in 1 .. Count loop
         if Data'Length-P < 6 then return; end if;
         NL:=MC_Codec.U16(Data,P+1);
         if MC_Codec.U32(Data,P+3) > 65_536 then return; end if;
         VL:=Natural(MC_Codec.U32(Data,P+3)); P:=P+6;
         if NL=0 or else NL>255 or else NL+VL>Data'Length-P then return; end if;
         declare S : String(1 .. NL); begin
            for J in S'Range loop S(J):=Character'Val(Data(P+J)); end loop;
            MC_Text.Set(Desired(I).Name,S,Status);
            if Status/=OK then return; end if;
            if S="security.capability" then Status:=Unsupported; return; end if;
         end;
         if I>1 and then MC_Text.Image(Desired(I).Name)<=MC_Text.Image(Desired(I-1).Name)
         then Status:=Invalid_Input; return; end if;
         P:=P+NL; Desired(I).Offset:=P+1; Desired(I).Length:=VL; P:=P+VL;
      end loop;
      if P/=Data'Length then Status:=Invalid_Input; return; end if;
      Get_Attributes(Descriptor,Link,Existing,E_Used,Status); if Status/=OK then return; end if;
      E_Count:=MC_Codec.U16(Existing,1); EP:=2;
      for I in 1 .. E_Count loop
         NL:=MC_Codec.U16(Existing,EP+1); VL:=Natural(MC_Codec.U32(Existing,EP+3)); EP:=EP+6;
         declare Name : String(1 .. NL); begin
            for J in Name'Range loop Name(J):=Character'Val(Existing(EP+J)); end loop;
            Found:=False;
            for A of Desired(1 .. Count) loop if MC_Text.Image(A.Name)=Name then Found:=True; end if; end loop;
            if not Found then
               if Name="security.selinux" then Status:=Denied; return; end if;
               declare C : aliased char_array:=To_C(Name); begin
                  if X_Remove(Descriptor,Link,C'Address)/=0 then Status:=IO_Error; return; end if;
               end;
            end if;
         end;
         EP:=EP+NL+VL;
      end loop;
      for A of Desired(1 .. Count) loop
         declare C : aliased char_array:=To_C(MC_Text.Image(A.Name));
                 Address : System.Address:=System.Null_Address; begin
            if A.Length>0 then Address:=Data(A.Offset)'Address; end if;
            if X_Set(Descriptor,Link,C'Address,Address,size_t(A.Length))/=0 then Status:=IO_Error; return; end if;
         end;
      end loop;
      Status:=OK;
   end Set_Attributes;
   procedure Get_Xattrs (F : File; Data : out Bytes; Used : out Natural; Status : out Outcome) is
   begin
      if F.Poisoned then Data:=(others=>0); Used:=0; Status:=Invalid_Input; return; end if;
      Get_Attributes(int(F.Handle),"",Data,Used,Status);
   end;
   procedure Set_Xattrs (F : File; Data : Bytes; Status : out Outcome) is
   begin
      if F.Poisoned then Status:=Invalid_Input; return; end if;
      Set_Attributes(int(F.Handle),"",Data,Status);
      if Status=OK then Sync(F,Status); end if;
   end;
   function Link_Endpoint(D : int; Name : MC_Text.Value) return String is
      Number : constant String:=int'Image(D);
   begin return "/proc/self/fd/" & Number(Number'First+1..Number'Last) & "/" & MC_Text.Image(Name); end;
   procedure Get_Link_Xattrs (R : Root; Path : String; Data : out Bytes;
                              Used : out Natural; Status : out Outcome) is
      D : int:=-1; Name : MC_Text.Value; V : Entry_Info;
   begin
      Data:=(others=>0); Used:=0;
      Stat(R,Path,V,Status); if Status/=OK then return; end if;
      if V.Kind/=Symbolic_Link then Status:=Invalid_Input; return; end if;
      Parent(R,Path,D,Name,Status); if Status/=OK then return; end if;
      -- /proc/self/fd is used only for a held directory descriptor and l* xattr
      -- calls (final component NOT followed). /proc must be the trusted procfs.
      Get_Attributes(D,Link_Endpoint(D,Name),Data,Used,Status); Drop(D);
   end;
   procedure Set_Link_Xattrs (R : Root; Path : String; Data : Bytes; Status : out Outcome) is
      D : int:=-1; Name : MC_Text.Value; V : Entry_Info;
   begin
      Stat(R,Path,V,Status); if Status/=OK then return; end if;
      if V.Kind/=Symbolic_Link then Status:=Invalid_Input; return; end if;
      Parent(R,Path,D,Name,Status); if Status/=OK then return; end if;
      Set_Attributes(D,Link_Endpoint(D,Name),Data,Status);
      if Status=OK and then Fsync(D)/=0 then Status:=Indeterminate; end if;
      Drop(D);
   end;
   procedure Close (F : in out File) is D : int:=int(F.Handle); begin Drop(D); F.Handle:=-1; F.Writable:=False; F.Poisoned:=False; end;
   procedure Close (R : in out Root) is D : int:=int(R.Handle); begin Drop(D); R.Handle:=-1; end;
   function Native (F : File) return Integer is (F.Handle);
   procedure List_Names (R : Root; Path : String; Names : out MC_Dirents.Listing; Status : out Outcome) is
      function Getdents64(F : int; Buffer : System.Address; N : size_t) return long
         with Import, Convention=>C, External_Name=>"getdents64";
      D : int:=-1; Dot : aliased char_array:=To_C(".");B : aliased Bytes(1..65_536);
      N : long; Before,After : Entry_Info;Work : MC_Dirents.Listing;
      Calls : Natural:=0;
   begin
      Names:=(others=><>);Status:=Invalid_Input;
      if R.Handle<0 then return;end if;
      if Path="" then D:=MC_Posix.Openat(int(R.Handle),Dot'Address,O_RDONLY+O_DIRECTORY+O_CLOEXEC+O_NOFOLLOW,0);
      elsif MC_Paths.Safe_Relative(Path) then D:=Open_Beneath(int(R.Handle),Path,O_RDONLY+O_DIRECTORY+O_CLOEXEC);
      else return;end if;
      if D<0 then Status:=IO_Error;return;end if;
      Stat_FD(D,Before,Status);if Status/=OK then Drop(D);return;end if;
      if Before.Kind/=Directory or else (Before.Mode and 8#022#)/=0 or else
        (Before.UID/=0 and then Before.UID/=Word(Euid)) then Status:=Denied;Drop(D);return;end if;
      loop
         if Calls=1_024 then Status:=Exhausted;Drop(D);return;end if;Calls:=Calls+1;
         N:=Getdents64(D,B'Address,B'Length);
         if N<0 then
            if Errno/=EINTR then Status:=IO_Error;Drop(D);return;end if;
         elsif N=0 then exit;
         elsif N>long(B'Length) then Status:=Corrupt;Drop(D);return;
         else MC_Dirents.Append_Linux64_LE(B(1..Natural(N)),Work,Status);
            if Status/=OK then Drop(D);return;end if;
         end if;
      end loop;
      Stat_FD(D,After,Status);Drop(D);if Status/=OK then return;end if;
      if Before/=After then Status:=Conflict;return;end if;
      MC_Dirents.Sort(Work);Names:=Work;Status:=OK;
   exception when others=>Drop(D);Names:=(others=><>);Status:=IO_Error;
   end List_Names;
end MC_FS;

# softflowd-cpp

[irino/softflowd](https://github.com/irino/softflowd)(Cによるフロー監視・NetFlowエクスポートデーモン)を、
[mecanik.dev の記事](https://mecanik.dev/ja/posts/c++-vs-rust-memory-safety-practical-examples-with-modern-c++/)
で示されているモダンC++のメモリ安全性プラクティスに沿って段階的に書き換えるプロジェクトです。

(English version: [README.en.md](README.en.md))

## 現在の進捗

| ステージ | 内容 | 状態 |
|---|---|---|
| Stage 1 | プロジェクト基盤 + コアのフロー管理(`freelist.c` + `sys-tree.h`の置き換え) | ✅ 完了 |
| Stage 2 | パケットキャプチャ(libpcap RAIIラッパー)+ パケット解析(IPv4/IPv6/TCP/UDP/ICMP) | ✅ 完了 |
| Stage 3 | NetFlow v1/v5/v9, IPFIX, PSAMP エクスポート | ✅ 完了 |
| Stage 4 | デーモン化・シグナル処理・`softflowctl`相当のCLI制御 + 元softflowdとのCLI完全互換 | ✅ 完了 |
| Stage 5 | MPLS(`-x`)・絶対時刻全形式(`-A`)・TCP/SCTPエクスポート(`-P`)・IPFIX biflow(`-b`)・PSAMP受信モード(`-R`)の本実装 | ✅ 完了 |
| Stage 6 | `softflowctl`コマンドセットを実マニュアルと完全一致させる修正 + 複数行レスポンス対応 | ✅ 完了 |
| Stage 7 | `softflowctl`のCLI文法を照合(問題なしと確認)+ `-R`のテンプレート管理を送信元ごとに分離して堅牢化 | ✅ 完了(一部継続中) |

## Stage 7: softflowctlのCLI文法照合 + -Rのテンプレート管理堅牢化

- `softflowctl`自体のコマンドライン文法(`-c ctl_sock command`)を原典と照合し、
  **既に一致していることを確認**しました(修正不要)。
- `PsampReceiver`のテンプレート管理を、テンプレートID単独ではなく
  **(送信元アドレス:ポート, テンプレートID)の組**でスコープするよう変更しました。
  複数のPSAMPエクスポータが同じテンプレートIDを異なるレコード形式で使っても
  (テンプレートIDはエクスポータごとに一意であればよく、全体で一意である必要は
  ないため)、互いのデコード結果が混線しなくなりました。`-i`ライブキャプチャ
  ループ側は`recv()`を`recvfrom()`に変更し、送信元アドレスを取得して渡します。
  2つの独立したエクスポータが偶然同じテンプレートIDを使うケースをテストで
  再現し、正しく分離されることを確認済みです。
- SCTPの実環境検証、ライブキャプチャのテストカバレッジ拡充は、この開発環境の
  制約(SCTPカーネルモジュール利用不可)により継続課題として残っています。

## Stage 6: softflowctlコマンドセットの是正

Stage 5完了時点で計画していた「設定ファイル読み込み」について原典
(softflowd(8)マニュアル)を再確認したところ、**`-f`オプションは存在せず、
OpenWrtパッケージ固有のUCI設定ラッパーがコマンドライン引数に変換している
だけ**と判明しました。誤った前提だったため計画から削除し、代わりに
`softflowctl(8)`の実際のコマンドセットを確認したところ、以前の実装
(`shutdown`/`exit`/`expire-all`/`delete-all`/`statistics`/`stop`/`start`)には
誤り・不足があることが分かりました。

### 修正したコマンド名

- `stop`→`stop-gather`、`start`→`start-gather`(元の正式名称に修正)

### 新規実装したコマンド

- `debug+`/`debug-`: デーモンのデバッグレベルを増減(`statistics`の出力にも反映)
- `dump-flows`: 追跡中の全フローの詳細情報を出力(`FlowTable`に新設した
  非破壊の`snapshot()`メソッドを使用。`expire_flows()`/`force_expire_oldest()`
  と異なり何も削除しない読み取り専用スナップショット)
- `timeouts`: 設定されているフロータイムアウト値を出力
- `send-template`: 次回エクスポート前にNetFlow v9テンプレートを強制再送
  (`Netflow9Exporter::force_template_resend()`を新設。他のエクスポート形式では
  「効果なし」と正直に応答)

### 制御プロトコルの複数行レスポンス対応

`dump-flows`の実装過程で、既存の制御プロトコル(`read_line`/`write_line`)が
**1行しか読み取れない**ため、複数行にわたるレスポンスが最初の改行で
切り詰められてしまう不具合を発見しました。`ControlClient`側に
`read_until_eof()`(サーバーが接続を閉じるまで読み続ける)を新設し、
`send_command()`をこちらに切り替えることで解決しました。サーバー側は
コマンド受信に`read_line()`(1行、こちらは正しい)を使い続け、レスポンス
送信後に接続を閉じる既存の設計とかみ合わせています。実際に複数フローを
追跡した状態で`dump-flows`が全行受信できることを確認済みです。

## Stage 5: 「受理はするが簡略化/未実装」だった機能の本実装

Stage 4で警告付きで簡略化していた5つのオプションを全て本実装しました。

### `-x number_of_mpls_labels`(MPLSラベルスタック解析)

パケット解析層(`softflowd.cpp`内)にMPLS EtherType(`0x8847`/`0x8848`)検出と
ラベルスタック走査を追加しました。ラベルスタックを全て走査してIPヘッダの
オフセットを求め(スタック内のラベル数に関わらず正しくIPパケットに到達)、
`-x`で指定した数だけ`Flow::mpls_labels`に格納し、NetFlow v9/IPFIXの
`mplsLabelStackSection1〜10`(IANA IE 70-79)フィールドとしてエクスポートします。
実際のMPLSカプセル化パケットを含むpcapで、ラベル値・bottom-of-stackビットが
正しくエクスポートされることを確認済みです。

### `-A sec|milli|micro|nano`(絶対時刻フォーマット全対応)

IPFIX/PSAMPの時刻フィールドを4形式全て実装しました。`sec`/`milli`は単純な
整数、`micro`/`nano`はRFC 7011の64ビットNTP形式(1900年起点の32ビット秒 +
32ビット小数部)でエンコードします(`micro`と`nano`は使用するIE番号が
異なるだけで、実際の精度は同じ32ビット小数部に由来する点を正直に注記して
います)。

### `-P udp|tcp|sctp`(トランスポート選択)

`ExportDestination`にトランスポート種別を追加し、UDP/TCPを完全実装しました
(実際にTCPリスナーへの送信を確認済み)。SCTPは`IPPROTO_SCTP`が利用可能な
環境でのみ試行し、接続失敗時は自動的にUDPへフォールバックして警告を出します
(SCTPカーネルモジュールの有無に依存するため)。

### `-b`(IPFIX biflow、RFC 5103)

双方向のトラフィックを1レコードにまとめ、逆方向のオクテット数/パケット数/
TCPフラグをRFC 5103のReverse Information Element(Private Enterprise Number
29305)としてエンコードする、簡略化ではない本来のbiflowエンコーディングを
実装しました。

### `-R receive_port`(PSAMP受信モード)

`PsampReceiver`クラスを新規実装し、IPFIXフレーミングのTemplate Set/Data Set
を汎用的にデコードします(認識できないフィールドは長さ分だけスキップするため、
このプロジェクトが送信する形式以外もある程度デコード可能な設計です)。
`-i`のライブキャプチャループに4つ目のpollディスクリプタとして統合し、
受信したPSAMPサンプルを通常のパケットキャプチャと同様に`FlowTable::record_packet()`
に投入します。実際に2つの`softflowd_cpp`インスタンス(送信側`-v psamp -n`、
受信側`-R`)間でend-to-end送受信・フロー追跡を確認済みです。

### 開発中に見つかった実環境依存の問題と修正

`-R`の検証中、ライブキャプチャループで**pcapの内部タイムアウトが信頼できない**
ことが判明しました。1つ目のパケットは正常に取得できても、2つ目の
`next_packet()`呼び出しが(データが無いにも関わらず)設定した100ms
タイムアウトを無視して無期限にブロックする挙動を、この検証環境で確認しました。
これを受けて、パケットドレインループを「`next_packet()`の内部タイムアウトに
任せる」のではなく「各呼び出しの直前に`poll(timeout=0)`で明示的に確認する」
方式に変更しました。これは元々のバッチ処理上限(1サイクル最大32パケット)の
安全策に加えた追加の防御で、環境によるpcapのタイムアウト挙動の差異に
依存しない、より堅牢な設計になっています。

## Stage 4: デーモン化 + 元softflowdとのCLI完全互換

`daemon.hpp/cpp`(元`daemon.c`)で`PidFile`(RAII)・`daemonize()`・`SignalPipe`
(self-pipeパターンによる安全なシグナル処理)を実装し、`softflowctl.hpp/cpp`
(元`softflowctl.c`)で制御プロトコル(改行区切りのテキストコマンド、
Unixドメインソケット)とクライアント本体を実装しました。`softflowd.cpp`
側には`-i`ライブキャプチャ用のイベントループ(`poll()`でシグナル/制御ソケット/
pcap fdを同時待機)を追加しています。

### コマンドライン引数を元softflowdと完全互換に

Stage 3までは独自の`--backend`/`--export`/`--live`等の長いオプション名を
使っていましたが、Stage 4で**元の`softflowd(8)`と全く同じgetoptベースの
1文字オプション**に置き換えました。既存のデプロイスクリプトやinitスクリプトが
そのまま使えることを目指しています。

```sh
# 元のsoftflowdと全く同じ書き方で動作します
softflowd_cpp -i eth0 -n 10.1.0.2:4432 -m 65536 -t udp=1m30s
softflowd_cpp -i eth0 -l -n 10.1.0.2:4432,10.1.0.3:4432
softflowd_cpp -v 9 -i eth0 -n 224.0.1.20:4432 -L 64
softflowd_cpp -i eth0 -p /var/run/sfd.pid.eth0 -c /var/run/sfd.ctl.eth0
```

実装済みのオプション(元softflowdと同じ意味・書式):

| オプション | 意味 |
|---|---|
| `-i [if_ndx:]interface` | ライブキャプチャするインターフェース |
| `-r pcap_file` | pcapファイルを読み込むモード(フォークしない、統計を表示して終了) |
| `-n host:port[,host:port...]` | NetFlow/IPFIX/PSAMPの実際の送信先(UDP、複数指定可) |
| `-N` | プロミスキャスモードにしない |
| `-l` | 複数`-n`宛先へのロードバランス送信(パケット単位のラウンドロビン) |
| `-L hoplimit` | 送信パケットのTTL/ホップリミット |
| `-e exporter_ip_address` | 送信元アドレス |
| `-S send_interface_name` | 送信インターフェース(`SO_BINDTODEVICE`) |
| `-p pidfile` / `-c ctlsock` | pidファイル/制御ソケットのパス |
| `-m max_flows` | 最大フロー数(デフォルト8192) |
| `-t timeout_name=time` | タイムアウト設定(`general`/`tcp`/`tcp.rst`/`tcp.fin`/`udp`/`maxlife`/`expint`)。`10m`や`1h30m`のような時間表記に対応 |
| `-d` | フォアグラウンド実行(デーモン化しない) |
| `-6` | IPv6フローの強制追跡 |
| `-D` | デバッグモード(`-d` `-6`を含意 + 追加ログ) |
| `-T track_level` | `ip`/`proto`/`full`(デフォルト)/`vlan`/`ether` |
| `-v netflow_version` | `1`/`5`(デフォルト)/`9`/`10`(IPFIX)/`psamp` |
| `-s sampling_rate` | 系統的サンプリング(1/N) |
| `-C capture_length` | スナップ長 |
| `-B size_bytes` | libpcapバッファサイズ(`pcap_create`/`pcap_activate`経由で実装) |
| `-h` | 使用方法表示 |
| 末尾の引数 | BPFフィルタ式として連結 |

### かつて「部分的な実装・未実装」だったオプション → Stage 5で全て本実装

Stage 4の時点では以下は簡略化/未実装でしたが、**Stage 5で全て本実装しました**
(詳細は下記「Stage 5」セクション参照)。`-P sctp`のみ、カーネルのSCTP
モジュールが無い環境では実行時にUDPへ自動フォールバックします:

| オプション | 状態 |
|---|---|
| `-P transport_protocol` | udp/tcp実装済み。sctpは環境依存(利用不可なら自動でudpにフォールバック) |
| `-A time_format` | sec/milli/micro/nano全て実装済み |
| `-b` | RFC 5103 biflowエンコーディングを実装済み |
| `-x number_of_mpls_labels` | MPLSラベルスタック解析を実装済み(NetFlow v9/IPFIX) |
| `-R receive_port` | PSAMP受信モードを実装済み(`-i`と併用時のみ) |

### このプロジェクト独自の拡張(元softflowdには存在しないオプション)

元の1文字オプションと衝突しないよう、GNUスタイルの長いオプション名にしています:

| オプション | 意味 |
|---|---|
| `--backend=hash\|tree` | フロー管理のデータ構造選択(既存Stage 1の機能) |
| `--export-out=PATH` | エクスポートパケットを追加でファイルにも書き出す(4バイトビッグエンディアン長さ付き) |
| `--max-runtime=SECONDS` | 指定秒数後に自動終了(主にテスト・デモ用) |

### `-a`(pcapファイルのタイムスタンプ調整)

`-r`でpcapファイルを読む際、`-a`を指定すると実際のキャプチャ時刻
(`pcap_pkthdr.ts`)を基準にフローの経過時間を計算します(未指定時はファイル
読み込み処理速度に基づく時刻を使用)。これにより、`PcapHandle::next_packet()`
が返す`CapturedPacket`に`wall_timestamp`フィールド(libpcap自身の記録時刻)を
追加しています。

### `main()`と`softflowctl`の実行ファイル分離

元プロジェクト同様、`softflowctl`は独立した実行ファイル(`softflowctl_cpp`)
です。`softflowctl.cpp`は制御プロトコルの共有ヘルパー(`read_line`/
`write_line`/`ControlClient`)と、`softflowctl_cpp`自身の`main()`(`#ifndef
SOFTFLOW_NO_MAIN`で保護)の両方を含みます。`softflowd_cpp`の制御ソケット
サーバー側は`softflowd.cpp`内に実装されており(元プロジェクトでも
`softflowd.c`側がリスニング/acceptを担当していたため)、`softflowctl.cpp`が
提供する共有プロトコルヘルパーだけをリンクします。

## Stage 3: NetFlow/IPFIX/PSAMPエクスポート

Stage 1/2と異なり、Stage 3のファイル(`netflow1`/`netflow5`/`netflow9`/`ipfix`/
`psamp`)は**`softflowd.hpp`/`softflowd.cpp`に統合していません**。元プロジェクト
でもこれらは明確に独立したファイルだったため、そのままの構成を踏襲しています:

```
include/softflow/
  netflow1.hpp   NetFlow v1(固定長レコード、テンプレートなし)
  netflow5.hpp   NetFlow v5(flow_sequence付き)
  netflow9.hpp   NetFlow v9(RFC 3954、テンプレートベース)
  ipfix.hpp      IPFIX(RFC 7011、絶対時刻フィールド)
  psamp.hpp      PSAMP(RFC 5477、パケット単位サンプリング、IPFIXフレーミング)
src/
  netflow1.cpp / netflow5.cpp / netflow9.cpp / ipfix.cpp / psamp.cpp
```

各エクスポータは`FlowTable::expire_flows()`/`force_expire_oldest()`が返す
`ExportRecord`(`FlowKey`+`Flow`のペア)のリストから、`ByteWriter`
(`softflowd.hpp`で定義、5ファイル共通の唯一の共有ユーティリティ)を使って
実際のワイヤフォーマットのバイト列を組み立てます。ネットワークI/Oは一切
含まれておらず、バイト列の組み立てだけを担当するため、実ネットワークなしで
決定的にユニットテスト可能です。

**元コードとの違い・簡略化点:**
- 元の`__packed`構造体+`htons()`/`htonl()`方式ではなく、`ByteWriter`による
  明示的なビッグエンディアン書き込みを使用(境界チェック付き、アライメント
  違反やバイトオーダ変換忘れが構造的に起きない)
- NetFlow v9/IPFIXは固定の2テンプレート(IPv4用/IPv6用)のみをサポート
  (元のような動的テンプレート管理は簡略化)
- PSAMPは実際のパケット単位サンプリングという性質上、`FlowTable`ではなく
  独自の`SampledPacket`型を入力とする設計にしています。RFC 5477が定義する
  セレクタ識別子やパケットハッシュ等のフィールドは省略し、タイムスタンプ・
  アドレス・ポート・プロトコル・観測長という実用上有用な部分集合のみを
  エクスポートします
- `softflowd_cpp`実行ファイルから`--export=netflow1|netflow5|netflow9|ipfix|psamp`
  で実際に試せます(下記参照)

```sh
./build/softflowd_cpp --export=netflow9 --export-out=out.bin path/to/capture.pcap
```

出力ファイルは各パケットに4バイトのビッグエンディアン長さプレフィックスを
付けて連結したものです(このプロジェクト独自のデモ用フレーミングであり、
NetFlow/IPFIX自体の仕様には含まれません)。

## 設計方針: なぜ softflowd.hpp / softflowd.cpp の2ファイルに集約したか

元のsoftflowdは`softflowd.c`/`softflowd.h`が中心となり、`main()`・パケット解析
(`ipv4_to_flowrec`/`ipv6_to_flowrec`/`transport_to_flowrec`)・フロー期限管理の
呼び出しがすべて`softflowd.c`に、フロー/期限構造体の定義が`softflowd.h`に
収まっていました。`freelist.c`/`treetype.h`/`sys-tree.h`は`struct FLOWTRACK`
(フロー集合+期限管理)の実装として補助的に存在していました。

このプロジェクトでは「モダンC++にする」という目的に反しない範囲で、可能な限り
元の1枚岩の構成に合わせています:

- **`include/softflow/softflowd.hpp`**: `Flow`/`FlowKey`/`FlowTable`/
  `PacketParser`/`PcapHandle`など、公開する型はすべてここに宣言(元の
  `softflowd.h` + `common.h` + `freelist.h`/`treetype.h`/`sys-tree.h`相当)
- **`src/softflowd.cpp`**: 上記すべての実装 + `main()`(元の`softflowd.c` +
  `freelist.c`相当)

パケット解析(`packet_parser.*`)とpcapキャプチャ(`capture.*`)は元プロジェクトに
対応する単体ファイルが存在しません(元は`softflowd.c`に直接書かれていました)。
以前のリビジョンでは分割していましたが、ご指摘を受けて`softflowd.hpp`/
`softflowd.cpp`に統合しました。

`freelist.c`+`treetype.h`+`sys-tree.h`の3ファイルで実現していた「フロー集合の
管理」は、`FlowTable`という1つのクラス(後述のとおりデータ構造を選択可能)に
統合し、同じく`softflowd.hpp`/`softflowd.cpp`に含めています。

### `main()`と単体テストの両立について

`softflowd.cpp`は`main()`を含む一方、テスト実行ファイル(`test_flow_table`,
`test_packet_parser`)も自前の`main()`を持つため、単純に同じ`.cpp`をリンクすると
シンボルが衝突します。これを避けるため、`softflowd.cpp`内の`main()`は
`#ifndef SOFTFLOW_NO_MAIN`で囲んであり、`CMakeLists.txt`は次のように
同じソースファイルを2通りにビルドします:

- `softflowd_cpp`実行ファイル: `softflowd.cpp`をそのままビルド(`main()`あり)
- `softflow_core`(テスト用オブジェクトライブラリ): `-DSOFTFLOW_NO_MAIN`付きで
  `softflowd.cpp`をビルド(`main()`なし)。各テストが自分の`main()`を提供する

## フロー管理のデータ構造を選択可能に(木構造 or ハッシュ)

元のsoftflowdは`sys-tree.h`による赤黒木(RB-tree)でフローを管理していました。
このプロジェクトでは`FlowTable`をテンプレートクラスにし、`FlowIndexBackend`で
バックエンドを選べるようにしています:

- `FlowIndexBackend::Hash` → `std::unordered_map<FlowKey, Flow>`(ハッシュ表、平均O(1))
- `FlowIndexBackend::Tree` → `std::map<FlowKey, Flow>`(libstdc++/libc++では実際に
  赤黒木として実装されており、元のsys-tree.hに最も近い代替)

**コンパイル時選択**(テンプレート、オーバーヘッドなし):

```cpp
softflow::FlowTable<softflow::FlowIndexBackend::Tree> table(65536);
```

**実行時選択**(`std::variant`ベースの`FlowTableRuntime`でラップ):

```cpp
softflow::FlowTableRuntime table(softflow::FlowIndexBackend::Tree, 65536);
```

`softflowd_cpp`実行ファイルは`--backend=hash`/`--backend=tree`オプションで
実行時に切り替えられます(下記参照)。

## ビルド方法

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
ctest --test-dir build --output-on-failure
```

依存: `libpcap-dev`。`CMAKE_BUILD_TYPE=Debug`(既定)では AddressSanitizer /
UndefinedBehaviorSanitizer が自動で有効になります。

```sh
# pcapファイルを処理し、統計を表示(-r、元softflowdと同じ書式)
./build/softflowd_cpp -r path/to/capture.pcap

# 赤黒木(std::map)バックエンドを使う(このプロジェクト独自の拡張)
./build/softflowd_cpp -r path/to/capture.pcap --backend=tree

# NetFlow v5をコレクタに実際に送信(元softflowdと同じ書式)
./build/softflowd_cpp -i eth0 -n 10.1.0.2:4432 -m 65536 -t udp=1m30s

# ライブキャプチャ + softflowctlで制御
./build/softflowd_cpp -i eth0 -d -c /tmp/sf.ctl &
./build/softflowctl_cpp -c /tmp/sf.ctl statistics
./build/softflowctl_cpp -c /tmp/sf.ctl shutdown
```

## メモリ安全性の対応表(記事の原則 → 適用箇所)

| 記事で挙げられているCの問題パターン | 元コードでの該当箇所 | このプロジェクトでの対処 |
|---|---|---|
| 生ポインタによる所有権の分散、二重解放/use-after-free | `freelist.c`(手動フリーリスト)、`FLOW*`↔`EXPIRY*`の相互生ポインタ | `FlowTable`内部の連想コンテナが唯一の所有者。期限管理は`std::multimap<TimePoint, FlowKey>`で「キー」を持つだけ |
| コピーによるイテレータの不整合 | (該当なし。元はそもそもコピー不可能な設計) | `FlowTable`はコピー禁止(`= delete`)、ムーブのみ許可。理由をコメントで明記 |
| 固定長バッファ+別変数の長さ、境界チェック漏れ | `mplsLabels[10]` + `mplsLabelStackDepth`、`ipv6_to_flowrec`の拡張ヘッダ走査 | `std::vector`/`std::span`で長さと領域を一体化 |
| キャストによる型パニング(strict-aliasing違反) | `(const struct ip *) pkt`等の生バイト列への構造体キャスト | `std::span<const std::uint8_t>`からのバイト単位読み出しのみ使用 |
| 手動リソース管理の閉じ忘れ | `pcap_t*`の手動`pcap_close`(一部のexit経路で漏れ) | `std::unique_ptr<pcap_t, PcapCloser>`によるRAII |
| 単位不明な生の整数(秒/ミリ秒の取り違え等) | タイムアウト値がすべて`int`(秒) | `std::chrono::seconds`等で単位を型に埋め込む |
| エラーを表す整数センチネル(`-1`, `PP_BAD_PACKET`等)の見落とし | `process_packet`の`int`戻り値 | `std::optional<ParsedPacket>` / 例外(`PcapError`)で失敗を型に反映 |
| 生ポインタで選択されたデータ構造の実装がハードコード | `sys-tree.h`による赤黒木がコンパイル時に固定 | `FlowIndexBackend`でテンプレート/実行時どちらでも選択可能 |

## 書き換え中に見つかった元コードの実バグ

調査の過程で、元のCコードに以下の潜在的な問題を見つけました(詳細はソースコード
中のコメント参照):

1. `ipv6_to_flowrec()`内の `eh6 = (const struct ip6_ext *) pkt + size;` は、
   キャストの優先順位により `size` を「バイト単位」ではなく
   `sizeof(struct ip6_ext)`単位で加算してしまう可能性があります。
2. `transport_to_flowrec()`のICMP/ICMPv6分岐には、TCP/UDPと違って
   `caplen`の事前チェックが無く、runtパケットに対して範囲外読み出しの
   可能性があります。

`softflowd.cpp`ではいずれも修正済みで、`tests/test_packet_parser.cpp`に
再発防止のためのテストケースを含めています。

## ディレクトリ構成

```
include/softflow/
  softflowd.hpp        Flow / FlowKey / FlowTable<Backend> / FlowTableRuntime /
                        PacketParser / PcapHandle / ByteWriter /
                        ExportDestination(Set) / TransportKind など
                        (元 softflowd.h + common.h + freelist.h/treetype.h/sys-tree.h)
  daemon.hpp            PidFile / daemonize() / SignalPipe(元 daemon.h)
  softflowctl.hpp       制御プロトコル定義 / ControlClient(元 softflowctl本体)
  netflow1.hpp           NetFlow v1(元 netflow1.h)
  netflow5.hpp           NetFlow v5(元 netflow5.h)
  netflow9.hpp           NetFlow v9 + MPLSラベルフィールド(元 netflow9.h)
  ipfix.hpp               IPFIX + MPLS/biflow(RFC 5103)/絶対時刻4形式(元 ipfix.h)
  psamp.hpp                PSAMP + PsampReceiver(-R受信モード用デコーダ、元 psamp.h)
src/
  softflowd.cpp           main() + 全実装 + ライブキャプチャイベントループ +
                          制御ソケットサーバー + PSAMP受信ソケット統合
                          (元 softflowd.c + freelist.c)
  daemon.cpp               (元 daemon.c)
  softflowctl.cpp           制御プロトコル実装 + softflowctl_cpp本体の main()
                          (元 softflowctl.c)
  netflow1.cpp / netflow5.cpp / netflow9.cpp / ipfix.cpp / psamp.cpp
tests/
  test_flow_table.cpp / test_packet_parser.cpp
  test_netflow1.cpp / test_netflow5.cpp / test_netflow9.cpp
  test_ipfix.cpp          biflow/絶対時刻フォーマット/MPLSのテストを含む
  test_psamp.cpp          PsampReceiverの往復テストを含む
  test_daemon.cpp         PidFile/SignalPipeのテスト
  test_softflowctl.cpp     制御プロトコルのテスト(std::threadでサーバー役を模擬、
                          OSプロセスを跨がない設計)
```

ビルドすると`softflowd_cpp`(デーモン本体)と`softflowctl_cpp`(制御クライアント)
の2つの実行ファイルが生成されます。

## 次のステップ(Stage 7の予定)

- ライブキャプチャのテストカバレッジ拡充(このプロジェクトの開発時に判明した、
  仮想化/サンドボックス環境でのpcapタイムアウト非信頼性のような環境依存の
  問題を継続的に検出できるようにする)
- `-R`のテンプレート管理の堅牢化(現在は単一の`PsampReceiver`が全テンプレートを
  無期限に保持する設計。実運用では複数エクスポータからの接続やテンプレートの
  再定義への対応強化が考えられます)
- SCTPの動作確認(このプロジェクトの開発・検証環境ではSCTPカーネルモジュールが
  利用できず、フォールバック経路のみ確認済み。実SCTP環境での検証が望まれます)
- `softflowctl`のコマンドライン引数(`-c ctl_sock command`)自体は元の
  `softflowctl(8)`と一致しているか、より詳細な照合の余地があります

続行のご指示があれば、この方針でStage 7に進みます。

# softflowd と rsoftflowd の完全互換性検証プラン

本ドキュメントは、C言語で実装されたオリジナル版 `softflowd` と、Rustで再実装された `rsoftflowd`（および `softflowctl` と `rsoftflowctl`）が完全な互換性を持っていることを証明するためのテスト方法およびアプローチを提案します。

---

## 1. 互換性を検証すべき 3 つの軸

完全な互換性を実証するためには、以下の3つの観点から検証を行う必要があります。

1. **CLI / コマンドライン引数の互換性 (Behavioral Compatibility)**
   - `softflowd` および `softflowctl` が受け付けるオプション、引数、環境変数の挙動が一致していること。
2. **コントロールソケット (Control Socket / IPC) のプロトコル互換性**
   - `softflowctl` (または `rsoftflowctl`) から UNIX ドメインソケット経由で送信されるコマンド（`statistics`, `expire all`, `shutdown` 等）に対して、双方のデーモンが全く同じ応答を返すこと。
   - 例: `rsoftflowctl` からオリジナル `softflowd` を操作できること、またその逆が成り立つこと。
3. **NetFlow/IPFIX パケット出力のバイナリレベル互換性 (Format Compatibility)**
   - 同一のパケットキャプチャ (pcap) 入力に対して、出力される NetFlow (v1, v5, v9) および IPFIX パケットの構造、フィールド値、シーケンス番号、タイムスタンプ計算が同一（または仕様上許容される範囲内）であること。

---

## 2. 具体的なテスト手法の提案

### テスト手法 1: 差分テスト (Differential Testing) によるパケット出力検証

最も信頼性が高い検証方法は、既知の pcap ファイルを両方のデーモンに読み込ませ、出力される NetFlow UDP パケットをキャプチャしてバイナリレベルで比較することです。

#### 構成イメージ
```
                   +--> softflowd (C)  --> [UDP Port 9991] --> NetFlowパケットA (pcap)
                   |
[入力 pcap ファイル]
                   |
                   +--> rsoftflowd (Go/Rust) --> [UDP Port 9992] --> NetFlowパケットB (pcap)
```

#### 手順:
1. テスト用の多様なトラフィックが含まれる pcap ファイル（例: TCP SYN/ACK/FIN, UDP, ICMP, IPv4, IPv6, フラグメントパケットなど）を用意します。
2. `softflowd` と `rsoftflowd` をそれぞれオフラインモード（`-r` オプションで pcap を指定）かつ同一のタイムアウト設定等で起動し、NetFlow コレクタ（`tcpdump` 等）に向けて NetFlow パケットを送信させます。
   ```bash
   # softflowd (C) の実行と出力キャプチャ
   softflowd -r test.pcap -n 127.0.0.1:9991 -d &
   tcpdump -i lo -w output_c.pcap udp port 9991 &

   # rsoftflowd (Rust) の実行と出力キャプチャ
   rsoftflowd -r test.pcap -n 127.0.0.1:9992 -d &
   tcpdump -i lo -w output_rust.pcap udp port 9992 &
   ```
3. 出力された `output_c.pcap` と `output_rust.pcap` を解析ツール（`tshark` または Python スクリプト）を用いてパースし、NetFlow レコードのフィールド（IPアドレス、ポート番号、パケット数、バイト数、TCPフラグ、タイムスタンプなど）が完全に一致するかを差分比較 (diff) します。

> [!TIP]
> システム起動時刻やパケット送信時のリアルタイムなタイムスタンプ差、ヘッダ内のシーケンス番号の初期値ランダム性など、仕様上どうしても一致しない動的フィールドについては、比較対象から除外（マスク）するスクリプトを用意すると効果的です。

---

### テスト手法 2: コントロールソケットの相互接続テスト (Cross-Control Test)

`softflowctl` と `rsoftflowctl` は、UNIXドメインソケット通信でデーモンと会話します。このやり取りの互換性をクロスで検証します。

#### 行列テスト:
| クライアント (CTL) | デーモン (Daemon) | 期待される結果 |
|---|---|---|
| オリジナル `softflowctl` | オリジナル `softflowd` | 正しく動作（リファレンス） |
| **Rust版 `rsoftflowctl`** | **オリジナル `softflowd`** | **疎通・コマンド実行・ステータス取得が正しく行えること** |
| **オリジナル `softflowctl`** | **Rust版 `rsoftflowd`** | **疎通・コマンド実行・ステータス取得が正しく行えること** |
| Rust版 `rsoftflowctl` | Rust版 `rsoftflowd` | 正しく動作 |

#### 検証コマンド例:
- `statistics`: 統計情報の出力フォーマットがテキストレベルで完全に一致しているか。
- `expire all`: キャッシュフローが即時エクスポートされ、コレクタにパケットが送信されるか。
- `shutdown`: デーモンが正常にクリーンアップ処理を行い終了するか。

---

### テスト手法 3: CLI オプションとヘルプの自動比較テスト

CLI引数のパーサーが同じ挙動をすることを確認するため、無効な引数やヘルプオプションを指定した際のエラー出力および終了コードを比較します。

#### 検証スクリプトの例 (Bash/Python):
```bash
# ヘルプ出力の確認
softflowd -h > help_c.txt 2>&1
rsoftflowd -h > help_rust.txt 2>&1
# 差異があるか確認（オプションの過不足がないか）
diff -u help_c.txt help_rust.txt

# 無効な引数指定時のエラーハンドリング確認
softflowd -z > /dev/null 2> err_c.txt; echo "C exit: $?"
rsoftflowd -z > /dev/null 2> err_rust.txt; echo "Rust exit: $?"
```

---

## 4. 自動テスト自動化 (CI) への組み込み提案

継続的インテグレーション (CI) にてこれらを実証するために、`tests` ディレクトリ以下に以下のような結合テストスクリプト（Python もしくは Rust の統合テスト）を追加することを推奨します。

1. **`pcap` ファイルベース of バイナリ回帰テスト**:
   - `tests/data/` にテスト用最小 `pcap` ファイルを配置。
   - `cargo test` 内で `rsoftflowd` を起動し、ダミー UDP ソケットで NetFlow パケットを受信。
   - 事前にオリジナル `softflowd` からダンプしておいた NetFlow パケット（動的ヘッダ等を除外したもの）の期待値バイナリと一致するかをアサートする。
2. **コントロールプレーンのモックテスト**:
   - Rust 側の結合テストコード (`tests/integration_tests.rs`) 内で、C言語版 `softflowd` のコントロールソケットプロトコル仕様に基づいた入出力を検証する。

---

## 5. 互換性チェックリスト

完全互換性の証明書（マトリクス）として、以下のテーブルの各項目を検証結果として文書化することを推奨します。

| カテゴリ | 検証項目 | 互換性ステータス | 備考 |
| :--- | :--- | :---: | :--- |
| **起動引数** | `-i` (Interface), `-r` (Read pcap), `-n` (Collector) | Ok / Pending / N/A | |
| | `-v` (NetFlow version: 1, 5, 9, 10/IPFIX) | Ok / Pending / N/A | |
| | `-m` (Max flows), `-t` (Timeouts) | Ok / Pending / N/A | |
| **制御コマンド**| `statistics` コマンドのテキスト出力 | Ok / Pending / N/A | |
| | `expire all` によるフローのフラッシュ | Ok / Pending / N/A | |
| | `shutdown` による正常終了 | Ok / Pending / N/A | |
| **パケット仕様**| NetFlow v5 レコードフォーマット | Ok / Pending / N/A | |
| | NetFlow v9 テンプレートおよびデータフロー | Ok / Pending / N/A | |
| | IPFIX (v10) テンプレートおよびデータフロー | Ok / Pending / N/A | |
| | タイムスタンプ精度 (ミリ秒/マイクロ秒) | Ok / Pending / N/A | |
| **挙動** | 双方向フローのトラッキングとタイムアウト挙動 | Ok / Pending / N/A | |

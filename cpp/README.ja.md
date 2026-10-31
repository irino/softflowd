# softflowd+

[irino/softflowd](https://github.com/irino/softflowd)(Cで書かれたフロー監視・
NetFlowエクスポートのデーモン)を、メモリ安全性に配慮したモダンなC++で書き直したものです。
実行ファイルは`softflowd+`と`softflowctl+`です。

親ディレクトリのC版が基準です。C++版は、コマンドライン、エクスポートするデータグラム、
制御ソケット、ログ、統計をC版に合わせ、バイト単位で比較します。設計と各Stageの変更点は
[ClaudeOutputDocument.ja.md](ClaudeOutputDocument.ja.md)を参照してください(Stage 8が
現在のC版への追従です)。

## ビルド

```sh
cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=Debug
cmake --build cpp/build -j
```

依存: libpcap。既定のビルドタイプは`Debug`で、AddressSanitizerと
UndefinedBehaviorSanitizerが有効です(`-DSOFTFLOW_ENABLE_SANITIZERS=OFF`で無効にできます)。
速度の測定は`-DCMAKE_BUILD_TYPE=Release`で行ってください。

`-DSOFTFLOW_NTOPNG=ON`で、ntopngへのエクスポート(`-v ntopng`、ntopng 6.0以降のTLV形式を
ZeroMQで送信)をビルドします。libzmqが必要です。

## APIドキュメント

```sh
cmake --build cpp/build --target doc      # HTMLはcpp/build/doc/html
```

Doxygen(図にはGraphviz)が必要です。ソースのコメントはDoxygenコメントで、C++コードの
働きを説明します。`@original`には、対応するC版の関数・変数の注記と、相違点を残しています。

## テスト

```sh
ctest --test-dir cpp/build --output-on-failure      # 単体テスト
```

C版との比較は`tools/softflowd_test_collector.py compat`です。先にC版をビルドします
(`autoreconf -if && ./configure && make`。ntopngを比較するときは`--enable-ntopng`を付けます)。

```sh
python3 tools/gen_ci_smoke_pcap.py /tmp/pc/http.cap
python3 tools/softflowd_test_collector.py compat --a ./softflowd --b ./cpp/build/softflowd+ \
  --ctl-a ./softflowctl --ctl-b ./cpp/build/softflowctl+ --strict --psamp --pcap-dir /tmp/pc \
  --no-benchmark --no-gauge-clock --no-cache
```

ライブの検査は`lo`を使い、rootが必要です(デーモンの検査は`/var/empty`も必要です)。
なければスキップします。同時に2つ走らせないでください。
`.github/scripts/cpp-test.sh [ntopng]`が全体を実行し、`.github/workflows/build.yml`のジョブ
`cpp-test`がそれを実行します。

## C版との既知の差

- バージョン表示は`v0.0.1`です(C版は`v1.1.1`)。
- 統計の`Flow table:`行は、ハッシュ関数が異なるため一致しません。
- 未実装: `--enable-ifname`(オプションレコードのinterfaceName)、互換コード
  (`--enable-legacy`、`--enable-compat-export`)、ntopng 5.x以前のJSONエクスポート。
- 確認したのは`lo`のみです。実NICとBSDは未確認です。
- デーモンは、停止後にpidファイルと制御ソケットが残ります(C版と同じです。chrootの中のユーザー
  `nobody`で動くためです)。

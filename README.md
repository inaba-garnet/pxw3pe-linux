# pxw3pe-linux

PLEXのPX-W3PE Rev1.3というPCIeテレビチューナーカード用のLinux DVBドライバです。
ブリッジにASICENのASV5220、制御チップにASIE5606を使っていて、ISDB-SとISDB-Tの
復調コアを2基ずつ積んでいます。

カードからはDVBアダプタが4つ見えます。

| アダプタ | チューナー | 復調コア |
|---------|-------|------------|
| `adapter0` | ISDB-S (S0) | 0x32 |
| `adapter1` | ISDB-S (S1) | 0x36 |
| `adapter2` | ISDB-T (T0) | 0x30 |
| `adapter3` | ISDB-T (T1) | 0x34 |

## 動作環境

- PLEX PX-W3PE Rev1.3
- x86-64のLinux、kernel 5.15系で動作確認
- 録画・選局はrecisdb 1.2系

---

## ファームウェアの準備

ASIE5606は、トランスポートストリームがホストに届く前にDESでスクランブルをかけてきます。
だから受信したストリームは、ドライバ側で解いてやらないと中身が読めません。

解くのに使うのはASV5606のチップシードと2本のDES鍵、それにXORシード。ドライバは
probe時に`request_firmware()`で`/lib/firmware/pxw3pe.fw`から読み込みます。

この鍵はカードのモデル固有のプロプライエタリな値なので、本リポジトリには含めていません。
`pxw3pe.fw`は公式ドライバ`asv5220_dtv.ko`から自分でビルドしてください。手順は
[`firmware/README.md`](firmware/README.md)にあります。

PLEX公式サイトでの配布はすでに終わっていますが、Wayback Machineから拾えるかもしれません。
https://web.archive.org/web/20131001000000*/http://plex-net.co.jp/plex/PX-SERIES_ver.1.0_Linux_Driver.zip

firmwareを入れずにロードしてもエラーにはなりません。ただしカード独自のスクランブルが
かかったままのストリームしか出てこないので、まともには使えません。これは放送波のARIB
MULTI2/CASとは別の層で、firmwareが無いとそこに届かず、B25デコードも実行できません。

---

## ビルドとインストール

ビルドには稼働中カーネルのヘッダと`gcc`、`make`が要ります。

```sh
make                      # pxw3pe.ko をビルド
sudo make install         # インストールして depmod まで実行
```

firmware blobをビルドするなら、手元の`asv5220_dtv.ko`のほかに`gcc`、`objcopy`、
`python3`も必要です。

```sh
python3 firmware/make_pxw3pe_fw.py --from-ko /path/to/asv5220_dtv.ko pxw3pe.fw
sudo cp pxw3pe.fw /lib/firmware/
```

あとはモジュールを読み込ませます。

```sh
sudo modprobe pxw3pe      # （または: sudo insmod pxw3pe.ko）
dmesg | tail
# 期待される出力: "key firmware 'pxw3pe.fw' loaded (descramble available)"
#                 "registered 4 DVB adapters"
```

### DKMSを使う場合

カーネルを更新しても自動で再ビルドされるので、入れ直す手間が省けます。

```sh
sudo cp -r . /usr/src/pxw3pe-1.0
sudo dkms add    -m pxw3pe -v 1.0
sudo dkms install -m pxw3pe -v 1.0
```

---

## 使い方

選局と録画は[`recisdb`](https://github.com/kazuki0824/recisdb-rs)で。以下はBSの例です。

```sh
recisdb checksignal -d /dev/dvb/adapter0/frontend0 -c BS15_0
recisdb tune -i /dev/dvb/adapter0/frontend0 -c BS15_0 -t 30 out.ts
```

### モジュールパラメータ

| パラメータ | 既定値 | 意味 |
|-------|---------|---------|
| `descramble` | `1` | 鍵firmwareがあるときASV5606のトランスポートDESデスクランブルを適用する |
| `use_msi` | `1` | MSI割り込みを使う（無効なら従来のINTx） |
| `s_acquire_retries` | `1` | キャリアがロックしないときにISDB-SのPLLと捕捉をリトライする回数 |
| `pkt_num`, `n_dmabuf` | — | DMAリングのチューニング |

## 注意事項

LNB給電はサポートしません。このリビジョンは基板上のレギュレータがDCをまともに出せず、
F端子で測っても0Vのままです。衛星LNBは外部電源から給電してください。

---

## ライセンス

GPL-2.0です。詳しくは[`LICENSE`](LICENSE)を見てください。

firmware blobの中の4つの暗号フィールドはカードのモデルに固有の値で、あなたがライセンスを
持つ`asv5220_dtv.ko`からビルド時に取り出します。これらはここでは配布していません。

## 謝辞

- ブリングアップの裏取りには、knight-rider氏のGPLドライバ[`ptx`](https://github.com/knight-rider/ptx)（同梱のPX-Q3PE用`pxq3pe`）と、nns779氏の[`px4_drv`](https://github.com/nns779/px4_drv)を参照しました。

# 詳細機能要件書：相互運用標準モデル LTI接続テストシステム

## 1. はじめに

### 1.1 プロジェクト概要
本システムは、日本の学習eポータル標準モデル（Ver. 5.00）に準拠したLTI 1.3接続（ツール起動・SSO）の動作検証を行うための開発者向けテストスイートです。

### 1.2 準拠仕様
- **LTI v1.3 Core Specification**
- **1EdTech OIDC Authorization Code Flow**
- **初等中等教育におけるシステム間連携のための相互運用標準モデル Ver. 5.00** (ICT CONNECT 21)

---

## 2. システムアーキテクチャ

### 2.1 コンポーネント構成
- **Frontend**: Vanilla JS + CSS (manabi-pocket-design-pattern準拠)
- **Backend API**: Node.js (Vercel Serverless Functions)
- **Database**: Firebase Firestore (ログ管理、証明書キャッシュ)
- **Keys**: RS256 署名用の秘密鍵・公開鍵ペア

### 2.2 ネットワークフロー
1. **Portal (Browser)**: 接続設定を入力し、Platform APIを叩く。
2. **Platform API**: OIDC Initiationを開始し、Toolへリダイレクト。
3. **Tool API**: Platformへ認可リクエストを送信。
4. **Platform API**: 認可実行（IDトークン発行）し、ToolへLaunch。
5. **Tool API**: IDトークンを表示。

---

## 3. 機能要件

### 3.1 LTI Platform シミュレータ機能
学習eポータル側の挙動をシミュレートする機能です。

- **OIDC Initiation (Phase 1)**
  - `iss`, `login_hint`, `target_link_uri`, `lti_message_hint`, `lti_deployment_id` の送出。
  - `prompt=none` の自動付与（日本仕様準拠）。
- **Authorization Request 検証 (Phase 2)**
  - 必須パラメータ（`client_id`, `scope`, `nonce`, `state`等）の厳密なチェック。
  - 仕様不適合時の詳細なエラー表示と「解決のヒント」の提供。
- **LTI Launch / IDトークン発行 (Phase 3)**
  - RS256アルゴリズムによるJWT署名。
  - `sub` (UUID v4), `roles` (フルURL), `deployment_id` (S_記法) の生成。
  - 学年情報のカスタムクレーム（`applic_grades`）への埋め込み。
- **JWKS配信**
  - 公開鍵を `application/json` 形式で `/api/platform/jwks` にて公開。

### 3.2 LTI Tool サンプル機能
接続を受ける側のツールのリファレンス実装です。

- **Initiation 受付**
  - プラットフォームからの開始リクエストを受け、認可エンドポイントへリダイレクト。
- **Launch 受付**
  - POSTされた `id_token` を受信し、デコード。
- **結果表示画面**
  - 受信したClaimsの詳細表示。
  - ユーザー属性（教員・生徒）、学年、コンテキストID等の可視化。

### 3.3 リアルタイム・ログ・ビジュアライザー
通信の透明性を確保するための機能です。

- **シーケンスシーケンス表示**
  - ステップ1（Initiation）、2（Auth）、3（Launch）の進行状況をステップ図で表示。
- **詳細イベントログ**
  - HTTPリクエスト/レスポンスの内容、バリデーション結果を時系列で表示。
  - エラー発生時のハイライト表示。

### 3.4 診断・証明ツール
相互運用性を担保するための拡張機能です。

- **JWKS Check**
  - 外部ツールのJWKSエンドポイントに接続し、鍵の取得と形式の妥当性を検証。
- **相互運用性証明書 (Interoperability Proof)**
  - 接続成功時に、技術的な証跡を含むデジタル証明書（JWTベース）を発行。
  - **検証用QRコード**: スマートフォン等でスキャンして、Platform側でホストされた検証画面により真正性を確認可能。
  - **PDF保存**: A4サイズの証明書として印刷・PDF出力が可能。

---

## 4. 非機能要件

### 4.1 セキュリティ
- **秘密鍵管理**: 環境変数およびセキュアなファイルシステムによる管理。
- **セッション整合性**: `state` および `nonce` によるリプレイ攻撃・CSRF対策。
- **匿名性**: `sub` クレームを含まない「匿名利用」のシミュレーション対応。

### 4.2 ユーザビリティ
- **Zero Burden（負担ゼロ）**: ツール開発者が設定をコピー＆ペーストするだけで即座にテスト可能。
- **レスポンシブデザイン**: デスクトップ・モバイル双方での閲覧を考慮。

---

## 5. データ定義

### 5.1 テストユーザー定義
以下のパターンをプリセットとして保持：
- 教員 (Teacher/Faculty)
- 児童生徒 (Learner/Student) × 学年別 (P6, J2, H3)
- 匿名ユーザー (Guest)

### 5.2 ログデータ
Firestore上の `logs` コレクションに以下を格納：
- `phase`: 通信のフェーズ（PHASE_1_INIT 等）
- `level`: INFO, SUCCESS, WARNING, ERROR
- `data`: 通信パラメータのJSON
- `sessionId`: 実行単位を特定するユニークID

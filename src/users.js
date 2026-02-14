/**
 * 学習eポータル標準V5.00準拠 テストユーザー定義
 * 
 * ロール要件: フルURL形式を必須とする
 * ID要件: sub (UUID v4) を必須とする
 * Deployment ID要件: 接頭辞 S_ を付加した学校コード
 */

const TEST_USERS = [
    {
        id: 'teacher_01',
        name: '佐藤 太郎',
        role: 'http://purl.imsglobal.org/vocab/lis/v2/institution/person#Instructor',
        sub: '550e8400-e29b-41d4-a716-446655440000', // UUID v4
        school_code: '131010000001', // 文科省学校コード (12桁想定)
        grade: ''
    },
    {
        id: 'teacher_02',
        name: '鈴木 花子',
        role: 'http://purl.imsglobal.org/vocab/lis/v2/institution/person#Instructor',
        sub: '6ba7b810-9dad-11d1-80b4-00c04fd430c8',
        school_code: '131010000001',
        grade: ''
    },
    {
        id: 'student_p6',
        name: '伊藤 健太',
        role: 'http://purl.imsglobal.org/vocab/lis/v2/institution/person#Student',
        sub: '7c9e6679-7425-40de-944b-e07fc1f90ae7',
        school_code: '131010000001',
        grade: 'P6' // 小6
    },
    {
        id: 'student_j2',
        name: '小林 大輔',
        role: 'http://purl.imsglobal.org/vocab/lis/v2/institution/person#Student',
        sub: 'ad6bd381-80e9-408a-bc36-397262f39871',
        school_code: '131010000002',
        grade: 'J2' // 中2
    },
    {
        id: 'student_h3',
        name: '佐々木 拓海',
        role: 'http://purl.imsglobal.org/vocab/lis/v2/institution/person#Student',
        sub: 'cf9537f0-2647-4977-9dfd-79e00662d075',
        school_code: '131010000003',
        grade: 'H3' // 高3
    }
];

module.exports = { TEST_USERS };

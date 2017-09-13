<?php
// +----------------------------------------------------------------------
// | Author: zhichengliang <atzcl0310@gmail.com>  Blog：https://www.zcloop.com
// +----------------------------------------------------------------------
namespace Atzcl;

use think\Db;
use think\Config;
use think\Session;
use think\Request;

class Auth
{
    /**
     * @var array 默认配置
     * */
    protected $_config = [
        'auth_on'               =>  true, // 权限开关
        // 认证方式：
        // 1为实时认证；每次验证，都重新读取数据库内的权限数据，如果对权限验证非常敏感的，建议使用实时验证
        // 2为登录认证 (即登录成功后，就把该用户用户的权限规则获取并保存到 session，之后就根据 session 值做权限验证判断)
        'auth_type'             =>  1,
        'auth_group'            =>  'auth_group', // 角色用户组数据表名
        'auth_group_access'     =>  'auth_group_access', // 用户-角色用户组关系表
        'auth_rule'             =>  'auth_rule', // 权限规则表
        'auth_user'             =>  'user_admin', // 用户信息表
    ];

    /**
     * @var array 请求类型
     */

    protected $_method = [
        'GET',
        'POST',
        'PUT',
        'DELETE'
    ];

    /**
     * @var object Request请求信息对象
     */
    protected $request;

    /**
     * @var string Session 作用域, 避免污染
     */
    protected static $prefix = 'atzcl';

    /**
     * 构造函数
     * @access protected
     */
    protected function __construct()
    {
        $this->request = Request::instance();

        // 判断是否有设置配置项
        if ($auth = Config::get('auth')) {
            // 合并,覆盖
            $this->_config = array_merge($this->_config, $auth);
        }
    }

    /**
     * 检查权限
     * @param $route string|array  需要验证的规则列表,支持逗号分隔的权限规则或索引数组
     * @param $uid  int           认证用户的id
     * @param $method boolean 验证请求方式
     * @param int $type 认证类型
     * @param string $mode 执行check的模式
     * @param string $relation 如果为 'or' 表示满足任一条规则即通过验证;如果为 'and'则表示需满足所有规则才能通过验证
     * @return bool               通过验证返回true;失败返回false
     */
    public static function check($route, $uid, $method = false, $type = 1, $mode = 'url', $relation = 'or')
    {
        $static = new static();
        // 判断是否开启 Auth 验证
        if ($static->_config['auth_on'] !== true) {
            return true;
        }

        // 获取用户需要验证的所有有效规则列表
        $authList = $static->getAuthList($uid, $type);

        if (is_string($route)) {
            $route = strtolower($route);
            // 判断传递过来，需要验证的规则字符串是否包含 , ：即多个验证规则
            if (strpos($route, ',') !== false) {
                // 切割
                $route = explode(',', $route);
            } else {
                $route = [$route];
            }
        }

        // 循环判断是否在用户组权限内
        $list = [];

        // check 传递的判断验证方式
        if ($mode === 'url') {
            // 如果为 url 验证，那就获取所有请求参数
            $REQUEST = unserialize(strtolower(serialize($static->request->param())));
        }

        foreach ($authList as $auth) {
            // 权限规则，通过正则匹配出 URL 后面的参数，如果存在参数的话
            // 示例: system/v1/cms_column?get=soft, 匹配结果是: get=soft
            $query = preg_replace('/^.+\?/U', '', $auth[0]);

            // 如果是验证 URL, 并且 $auth (验证的规则) 跟 $query （正则匹配过的）不相等的话，那就进入请求参数验证
            if ($mode === 'url' && $query !== $auth[0]) {

                // 解析规则中的param
                // parse_str() 函数把 url的参数 解析到变量中
                parse_str($query, $param);

                // 比较 $REQUEST（所有的请求参数）跟 $param （该条规则的参数数组）的键名跟键值，并返回交集
                $intersect = array_intersect_assoc($REQUEST, $param);

                // 把权限规则过滤成了去掉 url 参数的状态
                 $_auth = preg_replace('/\?.*$/U', '', $auth[0]);

                if (in_array($_auth, $route) && $intersect == $param) {

                    // 如果节点相符且url参数满足
                    // 判断是否需要验证请求方式
                    if ($method === false) {
                        $list[] = $auth[0];
                    } else {
                        if ($static->request->method() === $static->_method[$auth[1]]) {
                            $list[] = $auth[0];
                        }
                    }
                }
            } else {

                if (in_array($auth[0], $route)) {

                    // 判断请求类型 跟 需要验证的请求类型
                    if ($method === false) {
                        $list[] = $auth[0];
                    } else {
                        if ($static->request->method() === $static->_method[$auth[1]]) {
                            $list[] = $auth[0];
                        }
                    }
                }
            }
        }

        if ($relation === 'or' && !empty($list)) {
            return true;
        }

        // 比较数组键值，返回交集
        $diff = array_diff($route, $list);
        if ($relation === 'and' && empty($diff)) {
            return true;
        }

        return false;
    }

    /**
     * 根据用户id获取用户组,返回值为数组
     * @param  $uid int     用户id
     * @return array       用户所属的用户组
     *     array(2) {
                    [0] => array(4) {
                    ["uid"] => int(4)
                    ["group_id"] => int(2)
                    ["name"] => string(12) "文章编辑"
                    ["rules"] => string(51) "10,11,48,49,51,52,53,54,55,56,57,59,60,61,62,63,103"
                    }
                    [1] => array(4) {
                    ["uid"] => int(4)
                    ["group_id"] => int(3)
                    ["name"] => string(15) "微信管理员"
                    ["rules"] => string(118) "2,16,17,18,19,20,21,22,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151"
                    }
    }
     */
    public static function getGroups($uid)
    {
        // 保存用户存在的用户组信息
        static $groups = [];
        // 如果存在，就直接返回
        if (isset($groups[$uid])) {
            return $groups[$uid];
        }

        $static = new static();
        $auth_user =  $static->_config['auth_user'];
        $auth_group_access = $static->_config['auth_group_access'];
        $auth_group = $static->_config['auth_group'];

        // 利用视图查询，实现不依赖数据库视图的多表查询
        $user_groups = Db::view($auth_group_access, "{$auth_user}_id, {$auth_group}_id")
            ->view($auth_group, 'name, rules', "{$auth_group_access}.{$auth_group}_id = {$auth_group}.id", 'LEFT') // join
            ->where("{$auth_group_access}.{$auth_user}_id = '{$uid}' and {$auth_group}.status = '1'")
            ->select();
        $groups[$uid] = $user_groups ?: [];

        return $groups[$uid];
    }

    /**
     * 获得权限列表
     * @param integer $uid 用户id
     * @param integer $type
     * @return array
     */
    protected function getAuthList($uid, $type)
    {
        // 保存用户验证通过的权限列表
        static $_authList = [];
        $static = new static();

        $t = implode(',', (array) $type);
        if (isset($_authList[$uid . $t])) {
            return $_authList[$uid . $t];
        }

        // 判断权限验证方式
        if ($static->_config['auth_type']  === 2 && Session::has('_auth_list_' . $uid . $t)) {
            return Session::get('_auth_list_' . $uid . $t);
        }

        // 获取用户所属用户组
        $groups = static::getGroups($uid);

        $ids = []; // 保存用户所属用户组设置的所有权限规则 id
        foreach ($groups as $g) {
            $ids = array_merge($ids, explode(',', trim($g['rules'], ',')));
        }

        // 去除交叉重复的权限项
        $ids = array_keys(array_flip($ids));

        if (empty($ids)) {
            $_authList[$uid . $t] = [];
            return [];
        }

        // 组成获取所有权限详细信息的数组条件
        $map = [
            'id'        =>  ['in', $ids],
            'status'    =>  1
        ];

        // 获取用户组所有权限规则
        $rules = Db::name($static->_config['auth_rule'])->where($map)->field('condition, route, type')->select();

        // 循环规则，判断结果
        $authList = [];
        $method_type = [];
        foreach ($rules as $rule) {
            // 判断是否有附加规则
            if (!empty($rule['condition'])) {

                // 根据condition进行验证
                $user =$static->getUserInfo($uid); //获取用户信息,一维数组
                $command = preg_replace('/\{(\w*?)\}/', '$user[\'\\1\']', htmlspecialchars_decode($rule['condition']));
                // 使用 eval 函数执行
                // 把字符串作为PHP代码执行
                // 加 @ 是为了忽略可能会出现的错误
                // TODO: 后面会替代掉 eval
                @(eval('$condition=(' . $command . ');'));
                if ($condition) {
                    $authList[] = strtolower($rule['route']);
                    $method_type[] = $rule['type']; // 请求类型
                }
            } else {
                // 组成规则数组
                $authList[] = strtolower($rule['route']);
                $method_type[] = $rule['type']; // 请求类型
            }
        }

        // 如果权限验证类型为 2，那么就把权限规则数组保存到 session
        if ((new static())->_config['auth_type'] === 2) {
            // 规则列表结果保存到session
            Session::set('_auth_list_' . $uid . $t, $authList);
        }

        // 去掉重复的规则, 并添加权限规则限定的请求类型
        $new_auth_list = [];
        foreach (array_unique($authList) as $k => $v) {
            $new_auth_list[] = [
                $v, // 权限规则
                $method_type[$k] // 权限规则请求类型
            ];
        }

        // 组成权限规则数组, 并保存静态内存中
        $_authList[$uid . $t] = $new_auth_list;

        return $new_auth_list;
    }

    /**
     * 获得用户资料,根据自己的情况读取数据库
     * @param int $uid 用户 ID
     * @return array
     */
    protected function getUserInfo($uid)
    {
        static $userInfo = [];
        $static = new static();
        $user = Db::name($static->_config['auth_user']);
        // 获取用户表主键
        $_pk = is_string($user->getPk()) ? $user->getPk() : "{$static->_config['auth_user']}_id";
        if (!isset($userInfo[$uid])) {
            $userInfo[$uid] = $user->where($_pk, $uid)->find();
        }

        return $userInfo[$uid];
    }
}
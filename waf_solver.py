import re
import json
import time
import requests
from typing import Optional

def solve_aws_waf_challenge(
    html_response: str,
    user_agent: str,
    websiteurl: str = "https://www.paypay.ne.jp",
    proxy: Optional[str] = None,
    anysolver_api_key: Optional[str] = None
) -> str:
    """AWS WAF Challengeを解決してトークンを取得"""
    try:
        # gokuPropsとendpointを抽出
        goku_props_match = re.search(r'window\.gokuProps = ({.*?});', html_response, re.DOTALL)
        if not goku_props_match:
            raise Exception("AWS WAF Challenge: gokuPropsの抽出に失敗")
        
        goku_props_str = goku_props_match.group(1)
        goku_props = json.loads(goku_props_str)
        
        endpoint_match = re.search(r'src="https://([^"]+)/challenge\.js"', html_response)
        if not endpoint_match:
            raise Exception("AWS WAF Challenge: endpointの抽出に失敗")
        
        endpoint = endpoint_match.group(1)
        
        # AnySolver APIにタスクを作成
        create_task_url = "https://api.anysolver.com/createTask"
        
        task_payload = {
            "clientKey": "anysolver_01KTET6DCYX2D41EME5R9RVPJR",
            "task": {
                "type": "AWSWafToken",
                "websiteURL": websiteurl,
                "proxy": proxy or "http://6e33fbzp:9zjygb89@210.48.243.53:3126",
                "awsKey": goku_props.get("key"),
                "awsIv": goku_props.get("iv"),
                "awsContext": goku_props.get("context"),
                "awsChallengeJS": f"https://{endpoint}/challenge.js",
            }
        }
        
        # 不要なNullフィールドを削除
        task_payload["task"] = {
            k: v for k, v in task_payload["task"].items() if v is not None
        }
        
        # タスク作成リクエスト
        response = requests.post(
            create_task_url,
            json=task_payload,
            headers={"User-Agent": user_agent},
            timeout=10
        )
        response.raise_for_status()
        
        create_response = response.json()
        
        if create_response.get("errorId") != 0:
            error_desc = create_response.get('errorDescription', 'Unknown error')
            raise Exception(f"AnySolver タスク作成失敗: {error_desc}")
        
        task_id = create_response.get("taskId")
        if not task_id:
            raise Exception("AnySolver: タスクIDが返されませんでした")
        
        # AnySolver APIでタスク完了をポーリング
        get_result_url = "https://api.anysolver.com/getTaskResult"
        
        for attempt in range(30):
            time.sleep(2)
            
            result_response = requests.post(
                get_result_url,
                json={
                    "clientKey": anysolver_api_key,
                    "taskId": task_id
                },
                headers={"User-Agent": user_agent},
                timeout=10
            )
            result_response.raise_for_status()
            
            result = result_response.json()
            status = result.get("status")
            
            if status == "ready":
                solution = result.get("solution", {})
                aws_waf_token = solution.get("aws-waf-token")
                
                if not aws_waf_token:
                    raise Exception("AnySolver: ソリューションからトークンを取得できませんでした")
                
                return aws_waf_token
            
            elif status == "failed":
                error_code = result.get("errorCode", "Unknown")
                error_desc = result.get("errorDescription", "Unknown error")
                raise Exception(f"AnySolver AWS WAF Challenge解決失敗: {error_code} - {error_desc}")
        
        raise Exception("AWS WAF Challenge: タイムアウト（60秒以上待機）")
    
    except ImportError:
        raise Exception("AWS WAF Challenge解決に必要なライブラリがインストールされていません")
    except Exception as e:
        raise Exception(f"AWS WAF Challenge解決中にエラー: {str(e)}")

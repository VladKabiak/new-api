package model

import (
	"fmt"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
)

func cacheSetToken(token Token) error {
	if token.KeyHash == "" {
		return fmt.Errorf("token %d has no key hash to cache by", token.Id)
	}
	keyHash := token.KeyHash
	err := common.RedisHSetObj(fmt.Sprintf("token:%s", keyHash), &token, time.Duration(common.RedisKeyCacheSeconds())*time.Second)
	if err != nil {
		return err
	}
	return nil
}

func cacheDeleteToken(keyHash string) error {
	if keyHash == "" {
		return nil
	}
	err := common.RedisDelKey(fmt.Sprintf("token:%s", keyHash))
	if err != nil {
		return err
	}
	return nil
}

func cacheIncrTokenQuota(keyHash string, increment int64) error {
	if keyHash == "" {
		return nil
	}
	err := common.RedisHIncrBy(fmt.Sprintf("token:%s", keyHash), constant.TokenFiledRemainQuota, increment)
	if err != nil {
		return err
	}
	return nil
}

func cacheDecrTokenQuota(keyHash string, decrement int64) error {
	return cacheIncrTokenQuota(keyHash, -decrement)
}

func cacheSetTokenField(keyHash string, field string, value string) error {
	if keyHash == "" {
		return nil
	}
	err := common.RedisHSetField(fmt.Sprintf("token:%s", keyHash), field, value)
	if err != nil {
		return err
	}
	return nil
}

// CacheGetTokenByKey 从缓存中获取 token，如果缓存中不存在，则从数据库中获取
func cacheGetTokenByKey(keyHash string) (*Token, error) {
	if !common.RedisEnabled {
		return nil, fmt.Errorf("redis is not enabled")
	}
	if keyHash == "" {
		return nil, fmt.Errorf("empty token key hash")
	}
	var token Token
	err := common.RedisHGetObj(fmt.Sprintf("token:%s", keyHash), &token)
	if err != nil {
		return nil, err
	}
	// cacheSetToken stores the token without its handle; restore it so callers
	// that later need to evict or bill this token can do so from the struct.
	token.KeyHash = keyHash
	return &token, nil
}
